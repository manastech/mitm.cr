require "log"

class Mitm::CertManager
  Log = Mitm::Log.for("CertManager")
  @ssl_contexts = Hash(String, OpenSSL::SSL::Context::Server).new
  @mutex = Mutex.new
  @certs_path : Path
  @generator : CertGenerator

  def initialize(path, ca = true)
    root_path = Path.new(path)
    @certs_path = root_path / "hosts"
    Dir.mkdir_p @certs_path
    @generator = ca ? CACertGenerator.new(root_path) : SelfSignedCertGenerator.new
  end

  def context_for(host)
    @mutex.synchronize do
      @ssl_contexts[host] ||= begin
        cert_file = File.join(@certs_path, "#{host}.crt")
        key_file = File.join(@certs_path, "#{host}.key")

        unless File.exists?(cert_file) && File.exists?(key_file)
          Log.info { "Generating certificate for #{host}" }
          Process.run("openssl", ["genrsa", "-out", key_file, "2048"])
          @generator.generate(host, cert_file, key_file)
        end

        ssl_context = OpenSSL::SSL::Context::Server.new
        ssl_context.certificate_chain = cert_file
        ssl_context.private_key = key_file
        ssl_context
      end
    end
  end

  private module CertGenerator
    abstract def generate(host : String, cert_file : String, key_file : String)
  end

  private struct SelfSignedCertGenerator
    include CertGenerator

    def generate(host, cert_file, key_file)
      Process.run("openssl", ["req", "-x509", "-new", "-key", key_file, "-days", "50000", "-out", cert_file, "-subj", "/CN=#{host}"])
    end
  end

  private struct CACertGenerator
    include CertGenerator
    @ca_crt_path : String
    @ca_key_path : String
    @ca_srl_path : String

    def initialize(root_path)
      @ca_crt_path = File.join(root_path, "ca.crt")
      @ca_key_path = File.join(root_path, "ca.key")

      unless File.exists?(@ca_crt_path)
        raise "Could not find CA certificate file at #{@ca_crt_path}"
      end

      unless File.exists?(@ca_key_path)
        raise "Could not find CA private key file at #{@ca_key_path}"
      end

      @ca_srl_path = File.join(root_path, "ca.srl")
    end

    def generate(host, cert_file, key_file)
      req_file = "#{cert_file}.csr"
      Process.run("openssl", ["req", "-new", "-sha256", "-key", key_file, "-subj", "/CN=#{host}", "-out", req_file])
      Process.run("openssl", ["x509", "-req", "-in", req_file, "-CA", @ca_crt_path, "-CAkey", @ca_key_path, "-CAcreateserial", "-CAserial", @ca_srl_path, "-out", cert_file, "-days", "50000", "-sha256"])
    end
  end
end
