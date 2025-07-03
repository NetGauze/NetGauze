mod actor;
mod aggregator;
mod config;

pub use actor::AggregationActorHandle;
pub use config::AggregationConfig;

#[cfg(test)]
mod tests;
