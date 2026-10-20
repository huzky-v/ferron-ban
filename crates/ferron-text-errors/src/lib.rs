//! Plain-text error response module for Ferron.
//!
//! Provides a pipeline stage for the error pipeline (`HttpErrorContext`)
//! that generates one-line `"<status> <reason>"` bodies (e.g. `404 Not
//! Found`) instead of HTML error pages.

mod stage;
mod validator;

use std::collections::HashMap;
use std::sync::Arc;

use ferron_core::config::validator::ConfigurationValidator;
use ferron_core::loader::ModuleLoader;
use ferron_core::registry::RegistryBuilder;
use ferron_http::HttpErrorContext;

pub use stage::TextErrorStage;
pub use validator::TextErrorConfigurationValidator;

/// Module loader for the plain-text error response module.
#[derive(Default)]
pub struct FerronTextErrorsModuleLoader;

impl ModuleLoader for FerronTextErrorsModuleLoader {
    fn register_global_configuration_validators(
        &mut self,
        registry: &mut Vec<Box<dyn ConfigurationValidator>>,
    ) {
        registry.push(Box::new(TextErrorConfigurationValidator));
    }

    fn register_directives(&mut self, registry: &mut ferron_core::directives::DirectiveRegistry) {
        use ferron_core::directives::{Directive, DirectiveSubblock};
        registry.register(
            Directive {
                name: "text_errors",
                usage: "text_errors [bool]",
                description: "This directive enables plain-text error responses generated from the HTTP status code.",
                applicable_protocols: Some(&["http"]),
                global_only: false,
                subblock_link: None,
            },
            DirectiveSubblock::default(),
        );
    }

    fn register_per_protocol_configuration_validators(
        &mut self,
        registry: &mut HashMap<&'static str, Vec<Box<dyn ConfigurationValidator>>>,
    ) {
        registry
            .entry("http")
            .or_default()
            .push(Box::new(TextErrorConfigurationValidator));
    }

    fn register_stages(&mut self, registry: RegistryBuilder) -> RegistryBuilder {
        registry.with_stage::<HttpErrorContext, _>(|| Arc::new(TextErrorStage))
    }
}
