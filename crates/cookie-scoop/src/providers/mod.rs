pub mod chrome;
pub mod chromium;
pub mod edge;
pub mod firefox;
pub mod inline;
pub mod safari;

use crate::types::ProfileSelection;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProfileSelector<'a> {
    Default,
    Named(&'a str),
    All,
}

pub(crate) fn profile_selectors<'a>(
    selection: Option<&'a ProfileSelection>,
    fallback: Option<&'a str>,
) -> Vec<ProfileSelector<'a>> {
    match selection {
        Some(ProfileSelection::All) => vec![ProfileSelector::All],
        Some(ProfileSelection::Selected(profiles)) => {
            let profiles: Vec<_> = profiles
                .iter()
                .map(|profile| profile.trim())
                .filter(|profile| !profile.is_empty())
                .map(ProfileSelector::Named)
                .collect();
            if profiles.is_empty() {
                vec![ProfileSelector::Default]
            } else {
                profiles
            }
        }
        None => vec![fallback
            .map(str::trim)
            .filter(|profile| !profile.is_empty())
            .map_or(ProfileSelector::Default, ProfileSelector::Named)],
    }
}
