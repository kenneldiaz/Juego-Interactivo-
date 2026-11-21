-- Admin-only cancellation of the active search.
-- A canceled round uses RECLAMADO with no winner, matching the existing closed-round state.
create or replace function public.cancel_round(p_round_id bigint)
returns boolean
language plpgsql
security definer
set search_path = public, pg_temp
as $$
begin
  if not public.is_radar_admin() then
    raise exception 'Acceso de administrador requerido';
  end if;

  update public.rondas
  set estado = 'RECLAMADO',
      ganador_usuario = null,
      foto_prueba_url = null,
      reclamo_aprobado = false
  where id = p_round_id
    and estado = 'ACTIVO';

  return found;
end;
$$;

revoke all on function public.cancel_round(bigint) from public, anon;
grant execute on function public.cancel_round(bigint) to authenticated;

notify pgrst, 'reload schema';
