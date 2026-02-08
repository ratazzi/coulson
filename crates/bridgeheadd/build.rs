fn main() {
    capnpc::CompilerCommand::new()
        .file("tunnelrpc.capnp")
        .run()
        .expect("capnp schema compilation");
}
