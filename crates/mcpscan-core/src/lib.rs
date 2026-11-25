//! Static analysis for MCP server configs, agent configs and tool definitions.
//!
//! This crate is side-effect free: it never reads argv, never exits the process,
//! never executes a scanned server and never fetches a scanned URL.
#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod model;

pub mod parse;

pub mod discover;

pub mod resolve;

pub mod rules;
