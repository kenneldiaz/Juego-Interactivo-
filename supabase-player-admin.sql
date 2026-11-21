-- Radar Biker: device-bound player identities and administrator player tools.
-- Run after supabase-security.sql in the Supabase SQL Editor.

create table if not exists public.radar_player_devices (
  usuario text primary key
    check (usuario ~ '^[a-z0-9._]{1,24}$'),
  credential_hash text not null unique
    check (credential_hash ~ '^[0-9a-f]{64}$'),
  created_at timestamptz not null default now()
);

alter table public.radar_player_devices enable row level security;
revoke all on public.radar_player_devices from public, anon, authenticated;

create or replace function public.get_player_binding(p_credential_hash text)
returns text
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  v_usuario text;
begin
  if p_credential_hash is null or p_credential_hash !~ '^[0-9a-f]{64}$' then
    raise exception 'Credencial de dispositivo inválida';
  end if;

  select usuario into v_usuario
  from public.radar_player_devices
  where credential_hash = p_credential_hash;

  return v_usuario;
end;
$$;

revoke all on function public.get_player_binding(text) from public;
grant execute on function public.get_player_binding(text) to anon, authenticated;

create or replace function public.bind_player_device(
  p_usuario text,
  p_credential_hash text
)
returns text
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  v_bound_usuario text;
begin
  if p_usuario is null or p_usuario !~ '^[a-z0-9._]{1,24}$' then
    raise exception 'Usuario inválido';
  end if;
  if p_credential_hash is null or p_credential_hash !~ '^[0-9a-f]{64}$' then
    raise exception 'Credencial de dispositivo inválida';
  end if;

  select usuario into v_bound_usuario
  from public.radar_player_devices
  where credential_hash = p_credential_hash;

  if found then
    if v_bound_usuario <> p_usuario then
      raise exception 'Este dispositivo ya está vinculado a otro usuario';
    end if;
    return v_bound_usuario;
  end if;

  insert into public.radar_player_devices (usuario, credential_hash)
  values (p_usuario, p_credential_hash)
  on conflict do nothing;

  select usuario into v_bound_usuario
  from public.radar_player_devices
  where credential_hash = p_credential_hash;

  if found then
    if v_bound_usuario <> p_usuario then
      raise exception 'Este dispositivo ya está vinculado a otro usuario';
    end if;
    return v_bound_usuario;
  end if;

  raise exception 'Ese usuario ya está vinculado a otro dispositivo';
end;
$$;

revoke all on function public.bind_player_device(text, text) from public;
grant execute on function public.bind_player_device(text, text) to anon, authenticated;

do $$
declare
  p record;
begin
  for p in
    select policyname
    from pg_policies
    where schemaname = 'public'
      and tablename = 'jugadores_activos'
  loop
    execute format('drop policy if exists %I on public.jugadores_activos', p.policyname);
  end loop;
end
$$;

create policy "Radar: leer jugadores recientes"
  on public.jugadores_activos for select to anon, authenticated
  using (updated_at >= now() - interval '2 minutes');

revoke all on public.jugadores_activos from public, anon, authenticated;
grant select on public.jugadores_activos to anon, authenticated;

create or replace function public.publish_player_position(
  p_usuario text,
  p_credential_hash text,
  p_lat double precision,
  p_lng double precision
)
returns void
language plpgsql
security definer
set search_path = public, pg_temp
as $$
begin
  if p_usuario is null or p_usuario !~ '^[a-z0-9._]{1,24}$'
     or p_credential_hash is null or p_credential_hash !~ '^[0-9a-f]{64}$'
     or p_lat is null or p_lat not between -90 and 90
     or p_lng is null or p_lng not between -180 and 180 then
    raise exception 'Datos de posición inválidos';
  end if;

  if not exists (
    select 1 from public.radar_player_devices
    where usuario = p_usuario and credential_hash = p_credential_hash
  ) then
    raise exception 'El dispositivo no está vinculado a este usuario';
  end if;

  insert into public.jugadores_activos (usuario, lat, lng, updated_at)
  values (p_usuario, p_lat, p_lng, now())
  on conflict (usuario) do update
    set lat = excluded.lat,
        lng = excluded.lng,
        updated_at = excluded.updated_at;
end;
$$;

revoke all on function public.publish_player_position(text, text, double precision, double precision) from public;
grant execute on function public.publish_player_position(text, text, double precision, double precision) to anon, authenticated;

create or replace function public.remove_player_position(
  p_usuario text,
  p_credential_hash text
)
returns boolean
language plpgsql
security definer
set search_path = public, pg_temp
as $$
begin
  if not exists (
    select 1 from public.radar_player_devices
    where usuario = p_usuario and credential_hash = p_credential_hash
  ) then
    raise exception 'El dispositivo no está vinculado a este usuario';
  end if;

  delete from public.jugadores_activos where usuario = p_usuario;
  return found;
end;
$$;

revoke all on function public.remove_player_position(text, text) from public;
grant execute on function public.remove_player_position(text, text) to anon, authenticated;

drop function if exists public.claim_round(bigint, text, text);

create or replace function public.claim_round(
  p_round_id bigint,
  p_usuario text,
  p_credential_hash text,
  p_foto_prueba_url text
)
returns boolean
language plpgsql
security definer
set search_path = public, pg_temp
as $$
begin
  if p_usuario is null or p_usuario !~ '^[a-z0-9._]{1,24}$'
     or p_credential_hash is null or p_credential_hash !~ '^[0-9a-f]{64}$'
     or not exists (
       select 1 from public.radar_player_devices
       where usuario = p_usuario and credential_hash = p_credential_hash
     ) then
    raise exception 'El dispositivo no está vinculado a este usuario';
  end if;

  if p_foto_prueba_url is null
     or p_foto_prueba_url !~ '^https://djkbubafjktjapuouseq\.supabase\.co/storage/v1/object/public/stickers-fotos/prueba/[A-Za-z0-9._-]+$' then
    raise exception 'La foto de prueba debe estar en el bucket de pruebas';
  end if;

  update public.rondas
  set estado = 'RECLAMADO',
      ganador_usuario = p_usuario,
      foto_prueba_url = p_foto_prueba_url,
      reclamo_aprobado = false
  where id = p_round_id
    and estado = 'ACTIVO';

  return found;
end;
$$;

revoke all on function public.claim_round(bigint, text, text, text) from public;
grant execute on function public.claim_round(bigint, text, text, text) to anon, authenticated;

create or replace function public.admin_list_players()
returns table (
  usuario text,
  puntos integer,
  rondas_ganadas integer,
  registrado_en timestamptz,
  activo boolean
)
language plpgsql
stable
security definer
set search_path = public, pg_temp
as $$
begin
  if not public.is_radar_admin() then
    raise exception 'Acceso de administrador requerido';
  end if;

  return query
  select players.usuario,
         coalesce(r.puntos, 0),
         coalesce(r.rondas_ganadas, 0),
         d.created_at,
         exists (
           select 1 from public.jugadores_activos a
           where a.usuario = players.usuario
             and a.updated_at >= now() - interval '2 minutes'
         )
  from (
    select d.usuario from public.radar_player_devices d
    union
    select r.usuario from public.ranking r
    union
    select a.usuario from public.jugadores_activos a
    union
    select r.ganador_usuario from public.rondas r where r.ganador_usuario is not null
  ) players
  left join public.radar_player_devices d on d.usuario = players.usuario
  left join public.ranking r on r.usuario = players.usuario
  order by coalesce(r.puntos, 0) desc, players.usuario;
end;
$$;

revoke all on function public.admin_list_players() from public, anon;
grant execute on function public.admin_list_players() to authenticated;

create or replace function public.admin_clear_player_points(p_usuario text)
returns boolean
language plpgsql
security definer
set search_path = public, pg_temp
as $$
begin
  if not public.is_radar_admin() then
    raise exception 'Acceso de administrador requerido';
  end if;
  if p_usuario is null or p_usuario !~* '^[a-z0-9._]{1,24}$' then
    raise exception 'Usuario inválido';
  end if;

  update public.ranking
  set puntos = 0
  where lower(usuario) = lower(p_usuario);

  return found;
end;
$$;

revoke all on function public.admin_clear_player_points(text) from public, anon;
grant execute on function public.admin_clear_player_points(text) to authenticated;

create or replace function public.admin_delete_player(p_usuario text)
returns boolean
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  v_deleted boolean := false;
begin
  if not public.is_radar_admin() then
    raise exception 'Acceso de administrador requerido';
  end if;
  if p_usuario is null or p_usuario !~* '^[a-z0-9._]{1,24}$' then
    raise exception 'Usuario inválido';
  end if;

  delete from public.jugadores_activos where lower(usuario) = lower(p_usuario);
  v_deleted := v_deleted or found;

  delete from public.ranking where lower(usuario) = lower(p_usuario);
  v_deleted := v_deleted or found;

  update public.rondas
  set estado = case
        when id = (select id from public.rondas order by numero_ronda desc limit 1)
          and estado = 'RECLAMADO' then 'ACTIVO'
        else estado
      end,
      ganador_usuario = null,
      foto_prueba_url = null,
      reclamo_aprobado = false
  where lower(ganador_usuario) = lower(p_usuario);
  v_deleted := v_deleted or found;

  delete from public.radar_player_devices where usuario = lower(p_usuario);
  v_deleted := v_deleted or found;

  return v_deleted;
end;
$$;

revoke all on function public.admin_delete_player(text) from public, anon;
grant execute on function public.admin_delete_player(text) to authenticated;

drop policy if exists "Radar: admin borra pruebas" on storage.objects;
create policy "Radar: admin borra pruebas"
  on storage.objects for delete to authenticated
  using (
    bucket_id = 'stickers-fotos'
    and (storage.foldername(name))[1] = 'prueba'
    and public.is_radar_admin()
  );

notify pgrst, 'reload schema';
