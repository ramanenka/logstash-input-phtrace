# encoding: utf-8

require "logstash/inputs/base"
require "logstash/namespace"
require "logstash/util/socket_peer"

require "socket"

class LogStash::Inputs::Phtrace < LogStash::Inputs::Base
  config_name "phtrace"

  default :codec, "plain"

  # The address to listen on.
  config :host, :validate => :string, :default => "0.0.0.0"

  # The port to listen on.
  config :port, :validate => :number, :required => true, :default => 19229

  HOST_FIELD = "host".freeze
  PORT_FIELD = "port".freeze

  def initialize(*args)
    super(*args)

    # monkey patch TCPSocket to include socket peer
    TCPSocket.module_eval{include ::LogStash::Util::SocketPeer}

    # threadsafe socket bookkeeping
    @server_socket = nil
    @connection_sockets = {}
    @socket_mutex = Mutex.new

  end

  def register
    # fix_streaming_codecs

    # note that since we are opening a socket in register, we must also make sure we close it
    # in the close method even if we also close it in the stop method since we could have
    # a situation where register is called but not run & stop.

    self.server_socket = new_server_socket
  end

  def run(queue)
    run_server(queue)
  end

  def stop
    # force close all sockets which will escape any blocking read with a IO exception
    # and any thread using them will exit.
    # catch all rescue nil on close to discard any close errors or invalid socket
    server_socket.close rescue nil
    connection_sockets.each{|socket| socket.close rescue nil}
  end

  def close
    # see related comment in register: we must make sure to close the server socket here
    # because it is created in the register method and we could be in the context of having
    # register called but never run & stop, only close.
    # catch all rescue nil on close to discard any close errors or invalid socket
    server_socket.close rescue nil
  end

  private

  def run_server(queue)
    while !stop?
      begin
        socket = add_connection_socket(server_socket.accept)
        # start a new thread for each connection.
        server_connection_thread(queue, socket)
      rescue => e
        # if this exception occured while the plugin is stopping
        # just ignore and exit
        raise e unless stop?
      end
    end
  ensure
    # catch all rescue nil on close to discard any close errors or invalid socket
    server_socket.close rescue nil
  end

  def server_connection_thread(queue, socket)
    Thread.new(queue, socket, {}) do |q, s|
      begin
        @logger.debug? && @logger.debug("Accepted connection", :client => s.peer, :server => "#{@host}:#{@port}")
        handle_socket(s, s.peeraddr[3], s.peeraddr[1], q, @codec.clone)
      ensure
        delete_connection_socket(s)
      end
    end
  end

  def handle_socket(socket, client_address, client_port, queue, codec)
    peer = "#{client_address}:#{client_port}"
    while !stop?
      data = read(socket)
      decode(queue, data, client_address, client_port)
    end
  rescue EOFError
    @logger.debug? && @logger.debug("Connection closed", :client => peer)
  rescue Errno::ECONNRESET
    @logger.debug? && @logger.debug("Connection reset by peer", :client => peer)
  rescue => e
    # if plugin is stopping, don't bother logging it as an error
    !stop? && @logger.error("An error occurred. Closing connection", :client => peer, :exception => e, :backtrace => e.backtrace)
  ensure
    # catch all rescue nil on close to discard any close errors or invalid socket
    socket.close rescue nil
  end

  public
  def decode(queue, data, client_address, client_port)
    pos = 0

    while pos < data.bytesize do
      type = data.byteslice(pos).unpack("C")[0]
      pos += 1
      
      payload_length = data.byteslice(pos..pos + 4).unpack("V")[0];
      pos += 4

      raise(HeaderError) if pos + payload_length > data.bytesize 
      
      case type
      when 1
        event = decode_msg_request_begin(data, pos)
      when 2
        event = decode_msg_request_end(data, pos)
      when 3
        event = decode_msg_function_begin(data, pos)
      when 4
        event = decode_msg_function_end(data, pos)
      else
        raise(UnknownMessageError)
      end
      
      pos += payload_length
      
      event.set(HOST_FIELD, client_address) unless event.get(HOST_FIELD)
      event.set(PORT_FIELD, client_port) unless event.get(PORT_FIELD)

      decorate(event)
      queue << event
    end
  end
  
  protected
  def decode_msg_request_begin(data, pos)
    tsc = data.byteslice(pos..pos + 8).unpack("Q")[0]
    pos += 8

    Thread.current["request_uuid"] = uuid_unpack(data, pos)
    pos += 16
    
    return LogStash::Event.new({
      "id" => Thread.current["request_uuid"],
      "type" => "request_begin",
      "tsc" => tsc
    })
  end
  
  protected
  def decode_msg_request_end(data, pos)
    tsc = data.byteslice(pos..pos + 8).unpack("Q")[0]
    pos += 8

    return LogStash::Event.new({
      "id" => Thread.current["request_uuid"],
      "type" => "request_end",
      "tsc" => tsc
    })
  end
  
  protected
  def uuid_unpack(data, pos)
    return data.byteslice(pos..pos + 16).unpack("H8H4H4H4H12").join("-")
  end

  protected
  def decode_msg_function_begin(data, pos)
    tsc = data.byteslice(pos..pos + 8).unpack("Q")[0]
    pos += 8

    symbol_length = data.byteslice(pos..pos + 2).unpack("S")[0]
    pos += 2

    symbol_name = data.byteslice(pos..pos + symbol_length).unpack("Z*")[0]
    
    return LogStash::Event.new({
      "request_id" => Thread.current["request_uuid"],
      "type" => "function_begin",
      "tsc" => tsc,
      "symbol" => symbol_name
    })
  end

  protected
  def decode_msg_function_end(data, pos)
    tsc = data.byteslice(pos..pos + 8).unpack("Q")[0]
    pos += 8

    return LogStash::Event.new({
      "request_id" => Thread.current["request_uuid"],
      "type" => "function_end",
      "tsc" => tsc
    })
  end

  def read(socket)
    size = socket.sysread(8).unpack("Q")[0]
    socket.sysread(size)
  end

  def new_server_socket
    @logger.info("Starting tcp input listener", :address => "#{@host}:#{@port}")
    begin
      socket = TCPServer.new(@host, @port)
    rescue Errno::EADDRINUSE
      @logger.error("Could not start TCP server: Address in use", :host => @host, :port => @port)
      raise
    end
  end

  # threadsafe sockets bookkeeping

  def server_socket=(socket)
    @socket_mutex.synchronize{@server_socket = socket}
  end

  def server_socket
    @socket_mutex.synchronize{@server_socket}
  end

  def add_connection_socket(socket)
    @socket_mutex.synchronize{@connection_sockets[socket] = true}
    socket
  end

  def delete_connection_socket(socket)
    @socket_mutex.synchronize{@connection_sockets.delete(socket)}
  end

  def connection_sockets
    @socket_mutex.synchronize{@connection_sockets.keys.dup}
  end
end