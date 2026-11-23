use std::collections::BTreeSet;
use std::path::Path;

pub(crate) const READ_ONLY: rusqlite::OpenFlags =
    rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY.union(rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX);

pub(crate) fn table_columns(
    connection: &rusqlite::Connection,
    table: &str,
) -> rusqlite::Result<std::collections::HashSet<String>> {
    let mut statement = connection.prepare("SELECT name FROM pragma_table_info(?1)")?;
    let columns = statement.query_map([table], |row| row.get(0))?;
    columns.collect()
}

pub(crate) fn copy_database(source: &Path, destination: &Path) -> std::io::Result<()> {
    std::fs::copy(source, destination)?;
    for suffix in ["-wal", "-shm"] {
        let mut sidecar = source.as_os_str().to_owned();
        sidecar.push(suffix);
        let mut target = destination.as_os_str().to_owned();
        target.push(suffix);
        let _ = std::fs::copy(sidecar, target);
    }
    Ok(())
}

pub(crate) fn host_predicate(hosts: &[String], column: &str) -> String {
    let mut candidates = BTreeSet::new();
    for host in hosts {
        candidates.insert(host.as_str());
        let mut parent = host.as_str();
        while let Some((_, suffix)) = parent.split_once('.') {
            if !suffix.contains('.') {
                break;
            }
            candidates.insert(suffix);
            parent = suffix;
        }
    }
    if candidates.is_empty() {
        return "0".to_owned();
    }
    let clauses: Vec<_> = candidates
        .into_iter()
        .map(|candidate| {
            let host = candidate.replace('\'', "''");
            format!("({column} = '{host}' OR {column} = '.{host}' OR {column} LIKE '%.{host}')")
        })
        .collect();
    balanced_or(&clauses)
}

fn balanced_or(clauses: &[String]) -> String {
    if let [clause] = clauses {
        return clause.clone();
    }
    let (left, right) = clauses.split_at(clauses.len() / 2);
    format!("({} OR {})", balanced_or(left), balanced_or(right))
}
