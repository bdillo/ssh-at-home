use ssh_at_home::ca::{SshCa, generate_random_private_key};

fn main() {
    let ca = SshCa::with_new_keypair(ssh_key::Algorithm::Ed25519).unwrap();
    let principals = ["nixos"];

    let test_private_key = generate_random_private_key(ssh_key::Algorithm::Ed25519).unwrap();
    let test_public_key = test_private_key.public_key().to_owned();

    let cert = ca.sign_host_cert(&test_public_key, &principals).unwrap();
    println!("{}", cert.to_openssh().unwrap());
}
