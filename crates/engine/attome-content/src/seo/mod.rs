//! Search settings and structured data for content pages (roadmap E13-T4),
//! the page audit (E13-T7), and the SEO routes with what they call
//! (E13-T8).

/// E13-T11: what the SEO drafting action reads from a page.
pub mod agent;
pub mod audit;
pub mod routes;
pub mod settings;
pub mod site;
/// E13-T9: building the stored sitemaps.
pub mod sitemap;
pub mod structured_data;
