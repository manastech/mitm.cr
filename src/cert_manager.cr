class Mitm::CertManager
  @ssl_contexts = Hash(String, OpenSSL::SSL::Context::Server).new
  @mutex = Mutex.new
  @certs_path : Path
  @ca_crt_path : String
  @ca_key_path : String
  @ca_srl_path : String

  def initialize(path)
    @root_path = Path.new(path)
    @ca_crt_path = File.join(@root_path, "ca.crt")
    @ca_key_path = File.join(@root_path, "ca.key")
    @ca_srl_path = File.join(@root_path, "ca.srl")
    @certs_path = @root_path / "hosts"

    Dir.mkdir_p @certs_path
  end

  def context_for(host)
    @mutex.synchronize do
      @ssl_contexts[host] ||= begin
        cert_file = File.join(@certs_path, "#{host}.crt")
        key_file = File.join(@certs_path, "#{host}.key")

        unless File.exists?(cert_file) && File.exists?(key_file)
          req_file = File.join(@certs_path, "#{host}.csr")

          Process.run("openssl", ["genrsa", "-out", key_file, "2048"])
          Process.run("openssl", ["req", "-new", "-sha256", "-key", key_file, "-subj", "/CN=#{host}", "-out", req_file])
          Process.run("openssl", ["x509", "-req", "-in", req_file, "-CA", @ca_crt_path, "-CAkey", @ca_key_path, "-CAcreateserial", "-CAserial", @ca_srl_path, "-out", cert_file, "-days", "50000", "-sha256"])
        end

        ssl_context = OpenSSL::SSL::Context::Server.new
        ssl_context.certificate_chain = cert_file
        ssl_context.private_key = key_file
        ssl_context
      end
    end
  end
end
