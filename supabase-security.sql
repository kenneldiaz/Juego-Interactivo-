-- Radar Biker: RLS and privileged game operations.
-- Run in the Supabase SQL Editor as the project owner.

create table if not exists public.radar_admins (
  email text primary key check (email = lower(email))
);

alter table public.radar_admins enable row level security;
revoke all on public.radar_admins from public, anon, authenticated;

insert into public.radar_admins (email)
values ('kenneldiaz7@gmail.com')
on conflict (email) do nothing;

create or replace function public.is_radar_admin()
returns boolean
language sql
stable
security definer
set search_path = public, pg_temp
as $$
  select exists (
    select 1
    from public.radar_admins
    where email = lower(coalesce(auth.jwt() ->> 'email', ''))
  );
$$;

revoke all on function public.is_radar_admin() from public, anon;
grant execute on function public.is_radar_admin() to authenticated;

alter table public.rondas enable row level security;
alter table public.jugadores_activos enable row level security;
alter table public.ranking enable row level security;
alter table public.rondas add column if not exists reclamo_aprobado boolean not null default false;

do $$
declare
  p record;
begin
  for p in
    select schemaname, tablename, policyname
    from pg_policies
    where schemaname = 'public'
      and tablename in ('rondas', 'jugadores_activos', 'ranking')
  loop
    execute format('drop policy if exists %I on %I.%I', p.policyname, p.schemaname, p.tablename);
  end loop;
end
$$;

drop policy if exists "Juego público: leer rondas" on public.rondas;
drop policy if exists "Juego público: crear rondas" on public.rondas;
drop policy if exists "Juego público: actualizar rondas" on public.rondas;
drop policy if exists "Radar: lectura pública" on public.rondas;

create policy "Radar: lectura pública"
  on public.rondas for select to anon, authenticated
  using (true);

revoke all on public.rondas from public, anon, authenticated;
grant select on public.rondas to anon, authenticated;

drop policy if exists "Radar público: leer jugadores" on public.jugadores_activos;
drop policy if exists "Radar público: registrar jugadores" on public.jugadores_activos;
drop policy if exists "Radar público: actualizar jugadores" on public.jugadores_activos;
drop policy if exists "Radar: leer jugadores recientes" on public.jugadores_activos;
drop policy if exists "Radar: publicar posición" on public.jugadores_activos;
drop policy if exists "Radar: actualizar posición" on public.jugadores_activos;

create policy "Radar: leer jugadores recientes"
  on public.jugadores_activos for select to anon, authenticated
  using (updated_at >= now() - interval '2 minutes');

create policy "Radar: publicar posición"
  on public.jugadores_activos for insert to anon, authenticated
  with check (
    usuario ~ '^[A-Za-z0-9._]{1,24}$'
    and lat between -90 and 90
    and lng between -180 and 180
    and updated_at between now() - interval '2 minutes' and now() + interval '30 seconds'
  );

create policy "Radar: actualizar posición"
  on public.jugadores_activos for update to anon, authenticated
  using (true)
  with check (
    usuario ~ '^[A-Za-z0-9._]{1,24}$'
    and lat between -90 and 90
    and lng between -180 and 180
    and updated_at between now() - interval '2 minutes' and now() + interval '30 seconds'
  );

revoke all on public.jugadores_activos from public, anon, authenticated;
grant select, insert, update on public.jugadores_activos to anon, authenticated;

drop policy if exists "Ranking público: leer" on public.ranking;
drop policy if exists "Ranking público: reiniciar" on public.ranking;
drop policy if exists "Ranking: lectura pública" on public.ranking;

create policy "Ranking: lectura pública"
  on public.ranking for select to anon, authenticated
  using (true);

revoke all on public.ranking from public, anon, authenticated;
grant select on public.ranking to anon, authenticated;

create or replace function public.claim_round(
  p_round_id bigint,
  p_usuario text,
  p_foto_prueba_url text
)
returns boolean
language plpgsql
security definer
set search_path = public, pg_temp
as $$
begin
  if p_usuario is null or p_usuario !~ '^[A-Za-z0-9._]{1,24}$' then
    raise exception 'Usuario inválido';
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

revoke all on function public.claim_round(bigint, text, text) from public;
grant execute on function public.claim_round(bigint, text, text) to anon, authenticated;

create or replace function public.approve_claim(p_round_id bigint)
returns boolean
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  v_usuario text;
  v_puntos integer;
begin
  if not public.is_radar_admin() then
    raise exception 'Acceso de administrador requerido';
  end if;

  update public.rondas r
  set reclamo_aprobado = true
  where r.id = p_round_id
    and r.estado = 'RECLAMADO'
    and r.ganador_usuario is not null
    and r.reclamo_aprobado = false
  returning r.ganador_usuario, r.puntos into v_usuario, v_puntos;

  if not found then
    return false;
  end if;

  insert into public.ranking (usuario, puntos, rondas_ganadas)
  values (v_usuario, v_puntos, 1)
  on conflict (usuario) do update
    set puntos = public.ranking.puntos + excluded.puntos,
        rondas_ganadas = public.ranking.rondas_ganadas + 1;

  return true;
end;
$$;

revoke all on function public.approve_claim(bigint) from public, anon;
grant execute on function public.approve_claim(bigint) to authenticated;

create or replace function public.reopen_round(p_round_id bigint)
returns boolean
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  v_usuario text;
  v_puntos integer;
  v_aprobado boolean;
begin
  if not public.is_radar_admin() then
    raise exception 'Acceso de administrador requerido';
  end if;

  select ganador_usuario, puntos, reclamo_aprobado
  into v_usuario, v_puntos, v_aprobado
  from public.rondas
  where id = p_round_id and estado = 'RECLAMADO'
  for update;

  if not found then
    return false;
  end if;

  if v_aprobado and v_usuario is not null then
    update public.ranking
    set puntos = greatest(0, puntos - v_puntos),
        rondas_ganadas = greatest(0, rondas_ganadas - 1)
    where usuario = v_usuario;

    delete from public.ranking
    where usuario = v_usuario and puntos = 0 and rondas_ganadas = 0;
  end if;

  update public.rondas
  set estado = 'ACTIVO',
      ganador_usuario = null,
      foto_prueba_url = null,
      reclamo_aprobado = false
  where id = p_round_id;

  return true;
end;
$$;

revoke all on function public.reopen_round(bigint) from public, anon;
grant execute on function public.reopen_round(bigint) to authenticated;

create or replace function public.publish_round(
  p_titulo text,
  p_direccion text,
  p_premio text,
  p_puntos integer,
  p_lat double precision,
  p_lng double precision,
  p_foto_pista_url text default null
)
returns public.rondas
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  v_round public.rondas;
begin
  if not public.is_radar_admin() then
    raise exception 'Acceso de administrador requerido';
  end if;

  if length(trim(coalesce(p_titulo, ''))) not between 1 and 80
     or length(trim(coalesce(p_direccion, ''))) not between 1 and 120
     or length(trim(coalesce(p_premio, ''))) not between 1 and 100
     or p_puntos is null or p_puntos not between 1 and 100000
     or p_lat is null or p_lat not between -90 and 90
     or p_lng is null or p_lng not between -180 and 180 then
    raise exception 'Datos de ronda inválidos';
  end if;

  if p_foto_pista_url is not null
     and p_foto_pista_url !~ '^https://djkbubafjktjapuouseq\.supabase\.co/storage/v1/object/public/stickers-fotos/pista/[A-Za-z0-9._-]+$' then
    raise exception 'La foto pista debe estar en el bucket de pistas';
  end if;

  update public.rondas
  set estado = 'RECLAMADO',
      ganador_usuario = null,
      foto_prueba_url = null,
      reclamo_aprobado = false
  where estado = 'ACTIVO';

  insert into public.rondas (
    numero_ronda, titulo, direccion, premio, puntos, lat, lng,
    foto_pista_url, estado, ganador_usuario, foto_prueba_url, reclamo_aprobado
  )
  values (
    coalesce((select max(numero_ronda) from public.rondas), 0) + 1,
    trim(p_titulo), trim(p_direccion), trim(p_premio), p_puntos,
    p_lat, p_lng, p_foto_pista_url, 'ACTIVO', null, null, false
  )
  returning * into v_round;

  return v_round;
end;
$$;

revoke all on function public.publish_round(text, text, text, integer, double precision, double precision, text) from public, anon;
grant execute on function public.publish_round(text, text, text, integer, double precision, double precision, text) to authenticated;

create or replace function public.reset_ranking()
returns void
language plpgsql
security definer
set search_path = public, pg_temp
as $$
begin
  if not public.is_radar_admin() then
    raise exception 'Acceso de administrador requerido';
  end if;

  delete from public.ranking;
end;
$$;

revoke all on function public.reset_ranking() from public, anon;
grant execute on function public.reset_ranking() to authenticated;

insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values (
  'stickers-fotos',
  'stickers-fotos',
  true,
  10485760,
  array['image/jpeg', 'image/png', 'image/webp']
)
on conflict (id) do update
set public = true,
    file_size_limit = 10485760,
    allowed_mime_types = excluded.allowed_mime_types;

do $$
declare
  p record;
begin
  for p in
    select policyname
    from pg_policies
    where schemaname = 'storage'
      and tablename = 'objects'
      and concat_ws(' ', qual, with_check) ilike '%stickers-fotos%'
  loop
    execute format('drop policy if exists %I on storage.objects', p.policyname);
  end loop;
end
$$;

drop policy if exists "Fotos públicas: ver" on storage.objects;
drop policy if exists "Fotos públicas: subir" on storage.objects;
drop policy if exists "Radar: fotos públicas" on storage.objects;
drop policy if exists "Radar: jugadores suben pruebas" on storage.objects;
drop policy if exists "Radar: admin sube pistas" on storage.objects;

create policy "Radar: fotos públicas"
  on storage.objects for select to anon, authenticated
  using (bucket_id = 'stickers-fotos');

create policy "Radar: jugadores suben pruebas"
  on storage.objects for insert to anon, authenticated
  with check (
    bucket_id = 'stickers-fotos'
    and (storage.foldername(name))[1] = 'prueba'
    and name ~ '^prueba/[A-Za-z0-9._-]+\.(jpg|jpeg|png|webp)$'
    and storage.extension(name) in ('jpg', 'jpeg', 'png', 'webp')
  );

create policy "Radar: admin sube pistas"
  on storage.objects for insert to authenticated
  with check (
    bucket_id = 'stickers-fotos'
    and (storage.foldername(name))[1] = 'pista'
    and name ~ '^pista/[A-Za-z0-9._-]+\.(jpg|jpeg|png|webp)$'
    and storage.extension(name) in ('jpg', 'jpeg', 'png', 'webp')
    and public.is_radar_admin()
  );

do $$
begin
  if not exists (
    select 1 from pg_publication_tables
    where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = 'rondas'
  ) then
    alter publication supabase_realtime add table public.rondas;
  end if;
  if not exists (
    select 1 from pg_publication_tables
    where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = 'jugadores_activos'
  ) then
    alter publication supabase_realtime add table public.jugadores_activos;
  end if;
  if not exists (
    select 1 from pg_publication_tables
    where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = 'ranking'
  ) then
    alter publication supabase_realtime add table public.ranking;
  end if;
end
$$;

notify pgrst, 'reload schema';
