fn main() {
    ferron_entrypoint::init();
    let mut loaders = ferron_entrypoint::default_profile();
    loaders.push(Box::new(
        ferron_abuse_protection::FerronAbuseProtectionModuleLoader::default(),
    ));
    loaders.push(Box::new(ferron_text_errors::FerronTextErrorsModuleLoader));
    ferron_entrypoint::main(loaders);
}
