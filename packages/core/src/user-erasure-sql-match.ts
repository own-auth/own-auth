import { erasureEmailKeys, erasurePhoneKeys, erasureReferenceKeys } from "./user-erasure-subject.js";

export function pendingErasureCloudEventSql(dialect: "postgres" | "d1"): string {
  const pending = dialect === "postgres"
    ? "jsonb_array_elements_text(e.pending_cloud_events) pending(id)"
    : "json_each(e.pending_cloud_events) pending";
  return `exists (select 1 from own_auth_user_erasures e, ${pending}
    where ${dialect === "postgres" ? "pending.id" : "pending.value"} = own_auth_cloud_outbox.id)`;
}

/** Expressions and property names come only from the adapter, never from request text. */
export function erasureSqlMatch(dialect: "postgres" | "d1", column: string, subject: string): string {
  if (dialect === "postgres") return `own_auth_erasure_matches(${column}::jsonb, ${subject})`;
  const keys = (values: readonly string[]) => values.map((value) => `'${value}'`).join(",");
  return `exists (
    with recursive documents(doc) as (
      select ${column} where json_valid(${column})
      union all
      select n.atom from documents d, json_tree(d.doc) n
        where n.key = 'payload' and n.type = 'text' and json_valid(n.atom)
    )
    select 1 from documents d, json_tree(d.doc) n where n.type = 'text' and (
      (n.key in (${keys(erasureReferenceKeys)}) and exists (
        select 1 from json_each(${subject}, '$.references') r where r.value = n.atom))
      or (n.key in (${keys(erasureEmailKeys)}) and lower(n.atom) = lower(json_extract(${subject}, '$.email')))
      or (n.key in (${keys(erasurePhoneKeys)}) and n.atom = json_extract(${subject}, '$.phone'))
      or (n.key = 'targetId' and json_extract(d.doc, n.path || '.targetType') = 'user'
        and n.atom = json_extract(${subject}, '$.userId'))
    )
  )`;
}
