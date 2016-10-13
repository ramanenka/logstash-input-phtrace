# encoding: utf-8

module LogStash
  module Inputs
    class PhtraceLightEvent < LogStash::Event
      def initialize(data = {})
        @cancelled = false
        @data = data
        @accessors = LogStash::Util::Accessors.new(data)
      end
    end
  end
end
