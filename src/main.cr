require "./mitm"
require "http/server"

handlers = [
  HTTP::LogHandler.new,
  HTTP::ErrorHandler.new,
  Mitm::ProxyHandler.new,
]

server = HTTP::Server.new(handlers)
server.bind_tcp 8080

Log.info { "Listening on port 8080" }
server.listen
