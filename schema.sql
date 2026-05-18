create table if not exists launcher_users (
  id uuid primary key default gen_random_uuid(),
  login text not null unique,
  password_hash text not null,
  hwid text,
  expires_at timestamptz,
  is_banned boolean not null default false,
  created_at timestamptz not null default now()
);

create index if not exists launcher_users_login_idx on launcher_users (login);
create index if not exists launcher_users_hwid_idx on launcher_users (hwid);
