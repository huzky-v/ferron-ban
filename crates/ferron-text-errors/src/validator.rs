use ferron_core::config::validator::ConfigurationValidator;
use ferron_core::config::{ServerConfigurationBlock, ServerConfigurationValue};

/// Validator for the `text_errors` directive.
#[derive(Default)]
pub struct TextErrorConfigurationValidator;

impl ConfigurationValidator for TextErrorConfigurationValidator {
    fn validate_block(
        &self,
        config: &ServerConfigurationBlock,
        ctx: &mut ferron_core::config::validator::ConfigurationValidatorContext,
    ) -> Result<(), ferron_core::config::validator::ConfigurationValidationError> {
        let used_directives = &mut ctx.used_directives;

        ferron_core::validate_directive!(
            config,
            used_directives,
            text_errors,
            optional args(1) => [ServerConfigurationValue::Boolean(_, _)] | args(0) => [ServerConfigurationValue::Boolean(_, _)],
            {}
        );

        Ok(())
    }
}
