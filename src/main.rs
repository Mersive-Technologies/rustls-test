use rustls::{ClientConfig, ServerConfig, NoClientAuth, ClientSession, ServerSession, Session};
use std::fs;
use std::io::{BufReader, Read, Write};
use std::sync::Arc;
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener, TcpStream};
use std::time::Duration;

fn main() {

    let _ = std::thread::spawn(|| run_server());
    std::thread::sleep(Duration::from_millis(1000));
    run_client();

    println!("Hello, world!");
}

fn run_client() {
    let mut config = rustls::ClientConfig::new();
    config.dangerous()
        .set_certificate_verifier(Arc::new(danger::NoCertificateVerification {}));

    let dns_name = webpki::DNSNameRef::try_from_ascii_str("localhost").unwrap();
    let mut sess = rustls::ClientSession::new(&Arc::new(config), dns_name);
    let mut sock = TcpStream::connect("localhost:8007").unwrap();
    let mut tls_stream = rustls::Stream::new(&mut sess, &mut sock);
    let bytes = b"ping";
    tls_stream.write(&bytes[..]).unwrap();

    handle_read_client(&mut tls_stream);
}

fn run_server() {
    let mut server_cfg = ServerConfig::new(NoClientAuth::new());
    let ocsp = Vec::new();
    let certs = load_certs("/home/bgardner/cert1.pem");
    let privkey = load_private_key( "/home/bgardner/ukey1.pem" );
    server_cfg
        .set_single_cert_with_ocsp_and_sct(certs, privkey, ocsp, vec![])
        .expect("bad certificates/private key");
    let mut tls_session = rustls::ServerSession::new(&Arc::new(server_cfg));

    let loopback = Ipv4Addr::new(127, 0, 0, 1);
    let socket = SocketAddrV4::new(loopback, 8007);
    let listener = TcpListener::bind(socket).unwrap();
    let port = listener.local_addr().unwrap();
    println!("Listening on {}, access this port to end the program", port);
    let (mut tcp_stream, addr) = listener.accept().unwrap();
    println!("Connection received! {:?} is sending data.", addr);
    let mut tls_stream = rustls::Stream::new(&mut tls_session, &mut tcp_stream);

    handle_read(&mut tls_stream);

    let bytes = b"pong";
    tls_stream.write(&bytes[..]);
}

mod danger {
    use webpki;

    pub struct NoCertificateVerification {}

    impl rustls::ServerCertVerifier for NoCertificateVerification {
        fn verify_server_cert(
            &self,
            _roots: &rustls::RootCertStore,
            _presented_certs: &[rustls::Certificate],
            _dns_name: webpki::DNSNameRef<'_>,
            _ocsp: &[u8],
        ) -> Result<rustls::ServerCertVerified, rustls::TLSError> {
            Ok(rustls::ServerCertVerified::assertion())
        }
    }
}

fn handle_read(mut stream: &mut rustls::Stream<ServerSession, TcpStream>) {
    let mut buf = [0u8 ;4096];
    match stream.read(&mut buf) {
        Ok(_) => {
            let req_str = String::from_utf8_lossy(&buf);
            println!("{}", req_str);
        },
        Err(e) => println!("Unable to read stream: {}", e),
    }
}

fn handle_read_client(mut stream: &mut rustls::Stream<ClientSession, TcpStream>) {
    let mut buf = [0u8 ;4096];
    match stream.read(&mut buf) {
        Ok(_) => {
            let req_str = String::from_utf8_lossy(&buf);
            println!("{}", req_str);
        },
        Err(e) => println!("Unable to read stream: {}", e),
    }
}

fn load_certs(filename: &str) -> Vec<rustls::Certificate> {
    let certfile = fs::File::open(filename).expect("cannot open certificate file");
    let mut reader = BufReader::new(certfile);
    rustls_pemfile::certs(&mut reader).unwrap()
        .iter()
        .map(|v| rustls::Certificate(v.clone()))
        .collect()
}

fn load_private_key(filename: &str) -> rustls::PrivateKey {
    let keyfile = fs::File::open(filename).expect("cannot open private key file");
    let mut reader = BufReader::new(keyfile);

    loop {
        match rustls_pemfile::read_one(&mut reader).expect("cannot parse private key .pem file") {
            Some(rustls_pemfile::Item::RSAKey(key)) => return rustls::PrivateKey(key),
            Some(rustls_pemfile::Item::PKCS8Key(key)) => return rustls::PrivateKey(key),
            None => break,
            _ => {}
        }
    }

    panic!("no keys found in {:?} (encrypted keys not supported)", filename);
}
