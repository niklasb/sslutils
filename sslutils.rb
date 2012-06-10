require 'openssl'
require 'fileutils'

class SslUtils
  DEFAULT_KEY_SIZE = 4096

  def initialize(default_key_size = DEFAULT_KEY_SIZE)
    @bits = default_key_size
  end

  def generate_rsa_key(bits)
    bits ||= @bits
    OpenSSL::PKey::RSA.new(bits) { |p, n|
      case p
      when 0; STDERR.putc "."  # BN_generate_prime
      when 1; STDERR.putc "+"  # BN_generate_prime
      when 2; STDERR.putc "*"  # searching good prime,
                               # n = #of try,
                               # but also data from BN_generate_prime
      when 3; STDERR.putc "\n" # found good prime, n==0 - p, n==1 - q,
                               # but also data from BN_generate_prime
      else;   STDERR.putc "*"  # BN_generate_prime
      end
    }
  end

  def create_ca(openssl_bin, config)
    ca_dir         = File.expand_path(config['dir'], ROOT)
    keyfile        = File.join(ca_dir, "private/cakeypair.pem")
    certfile       = File.join(ca_dir, "cacert.pem")
    certfile_pkcs7 = File.join(ca_dir, "cacert.p7b")

    key_password = config['key_password'].to_s || "1234"

    if File.exists?(ca_dir)
      # read CA certificate
      STDERR.puts "Reading CA cert from %s" % certfile.inspect
      cert = OpenSSL::X509::Certificate.new(File.read(certfile))

      STDERR.puts "Reading CA keypair from %s" % keyfile.inspect
      keypair = OpenSSL::PKey::RSA.new(
        File.read(keyfile),
        key_password)

      return [cert, keypair]
    end

    STDERR.puts "Generating CA..."

    FileUtils.makedirs ca_dir
    Dir.mkdir File.join(ca_dir, 'private'), 0700

    keypair = generate_rsa_key(config['bits'])

    cert = OpenSSL::X509::Certificate.new
    cert.subject = cert.issuer = OpenSSL::X509::Name.new(
      config['subject'].to_a)
    cert.not_before = Time.now
    cert.not_after = Time.now + config['valid_days'] * 24*60*60
    cert.public_key = keypair.public_key
    cert.serial = 0x0
    cert.version = 2 # X509v3

    ef = OpenSSL::X509::ExtensionFactory.new
    ef.subject_certificate = cert
    ef.issuer_certificate = cert
    cert.extensions = [
      ef.create_extension("basicConstraints","CA:TRUE", true),
      ef.create_extension("nsComment", config['comment'] || "CA"),
      ef.create_extension("subjectKeyIdentifier", "hash"),
      ef.create_extension("keyUsage", "cRLSign,keyCertSign", true),
    ]
    cert.add_extension ef.create_extension(
      "authorityKeyIdentifier",
      "keyid:always,issuer:always")
    cert.sign keypair, OpenSSL::Digest::SHA1.new

    keypair_pem = keypair.to_pem(
      OpenSSL::Cipher::DES.new(:EDE3, :CBC),
      key_password)

    STDERR.puts "Writing keypair to %s" % keyfile.inspect
    File.open keyfile, "w", 0400 do |fp|
      fp << keypair_pem
    end

    STDERR.puts "Writing cert to %s" % certfile.inspect
    File.open certfile, "w" do |f|
      f << cert.to_pem
    end

    STDERR.puts "Writing PKCS7 cert to %s" % certfile_pkcs7.inspect
    system openssl_bin, "crl2pkcs7", "-nocrl",
                        "-certfile", certfile,
                        "-out", certfile_pkcs7

    STDERR.puts "Done generating certificate for #{cert.subject}"

    [cert, keypair]
  end

  def create_self_signed_cert(subject, opts)
    opts = {
      :from    => Time.now,
      :to      => Time.now + (365*24*60*60),
      :serial  => 0,
    }.merge(opts)

    key = opts[:key] || generate_rsa_key(DEFAULT_KEY_SIZE)

    cert = OpenSSL::X509::Certificate.new
    cert.version = 3
    cert.serial = opts[:serial]

    unless subject.is_a? OpenSSL::X509::Name
      subject = OpenSSL::X509::Name.new(subject)
    end

    cert.subject = cert.issuer = subject
    cert.not_before = opts[:from]
    cert.not_after  = opts[:to]
    cert.public_key = key.public_key

    ef = OpenSSL::X509::ExtensionFactory.new(nil, cert)
    ef.issuer_certificate = cert
    ex = [
      ef.create_extension("basicConstraints","CA:FALSE"),
      ef.create_extension("keyUsage", "keyEncipherment"),
      ef.create_extension("subjectKeyIdentifier", "hash"),
      ef.create_extension("extendedKeyUsage", "serverAuth"),
    ]

    if opts[:comment]
      ex << ef.create_extension(
          "nsComment",
          opts[:comment])
    end

    ex << ef.create_extension("authorityKeyIdentifier",
                              "keyid:always,issuer:always")
    cert.extensions = ex

    # sign
    cert.sign(key, OpenSSL::Digest::SHA1.new)
    cert
  end

  def create_ca_signed_cert(subject, ca_cert, ca_key, opts)
    opts = {
      :from    => Time.now,
      :to      => Time.now + (365*24*60*60),
      :serial  => 0,
    }.merge(opts)

    key = opts[:key] || generate_rsa_key(DEFAULT_KEY_SIZE)

    cert = OpenSSL::X509::Certificate.new
    cert.version = 3
    cert.serial = opts[:serial]

    unless subject.is_a? OpenSSL::X509::Name
      subject = OpenSSL::X509::Name.new(subject)
    end

    cert.subject    = subject
    cert.issuer     = ca_cert.subject
    cert.not_before = opts[:from]
    cert.not_after  = opts[:to]
    cert.public_key = key.public_key

    ef = OpenSSL::X509::ExtensionFactory.new
    ef.subject_certificate = cert
    ef.issuer_certificate = ca_cert
    ex = [
      ef.create_extension("basicConstraints", "CA:FALSE", true),
      ef.create_extension("keyUsage", "digitalSignature,keyEncipherment"),
      ef.create_extension("subjectKeyIdentifier", "hash"),
      ef.create_extension("extendedKeyUsage", "serverAuth"),
    ]

    if opts[:comment]
      ex << ef.create_extension(
        "nsComment",
        opts[:comment])
    end
    cert.extensions = ex

    # sign
    cert.sign ca_key, OpenSSL::Digest::SHA1.new
    cert
  end

end
