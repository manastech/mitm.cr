module Mitm::CertManager
  @@ssl_contexts = Hash(String, OpenSSL::SSL::Context::Server).new
  @@mutex = Mutex.new

  def self.context_for(host)
    @@mutex.synchronize do
      @@ssl_contexts[host] ||= begin
        cert_file = "certs/#{host}.crt"
        key_file = "certs/#{host}.key"

        unless File.exists?(cert_file) && File.exists?(key_file)
          req_file = "certs/#{host}.csr"
          `openssl genrsa -out #{key_file} 2048`
          `openssl req -new -sha256 -key #{key_file} -subj "/CN=#{host}" -out #{req_file}`
          `openssl x509 -req -in #{req_file} -CA ca.crt -CAkey ca.key -CAcreateserial -out #{cert_file} -days 50000 -sha256`
        end

        ssl_context = OpenSSL::SSL::Context::Server.new
        ssl_context.certificate_chain = cert_file
        ssl_context.private_key = key_file
        ssl_context
      end
    end
  end
end
