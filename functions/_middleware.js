/**
 * SilverCloud — protección por contraseña para Cloudflare Pages.
 * Va en functions/_middleware.js — se aplica a TODAS las rutas.
 * Requiere la variable de entorno SC_PASSWORD en el panel de Cloudflare.
 */

const COOKIE = 'sc_auth';
const DIAS = 30;

async function hash(texto) {
  const datos = new TextEncoder().encode('silvercloud::' + texto);
  const buf = await crypto.subtle.digest('SHA-256', datos);
  return Array.from(new Uint8Array(buf))
    .map(b => b.toString(16).padStart(2, '0')).join('');
}

function pantallaLogin(conError) {
  return `<!DOCTYPE html>
<html lang="es" data-darkreader-mode="ignore">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="color-scheme" content="dark only">
<title>SilverCloud Advisors</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Libre+Baskerville:ital,wght@0,400;0,700;1,400&family=Open+Sans:wght@300;400;600&display=swap" rel="stylesheet">
<style>
  :root { color-scheme: dark; }
  html { background:#0d1117; }
  body { margin:0; min-height:100vh; display:flex; align-items:center; justify-content:center;
    background:#0d1117; color:#d8dee9; font-family:'Open Sans',sans-serif; font-weight:300;
    font-size:14px; padding:24px; }
  .caja { width:min(380px,100%); }
  h1 { font-family:'Libre Baskerville',serif; font-style:italic; font-weight:400; font-size:26px;
    color:#f0f6fc; margin:0 0 4px; }
  h1 strong { color:#5b86c7; font-weight:700; }
  .linea { font-size:11px; letter-spacing:2px; text-transform:uppercase; color:#8b95a8;
    margin-bottom:26px; padding-bottom:20px; border-bottom:2px solid #5b86c7; }
  label { display:block; font-size:10px; letter-spacing:1.5px; text-transform:uppercase;
    color:#6b748a; margin-bottom:6px; }
  input { width:100%; background:#0d1117; border:1px solid #5b86c7; color:#f0f6fc;
    font-family:inherit; font-size:15px; padding:10px 12px; border-radius:2px; outline:none; }
  input:focus { box-shadow:0 0 0 2px rgba(91,134,199,.25); }
  button { width:100%; margin-top:14px; background:#1a2030; border:1px solid #5b86c7; color:#5b86c7;
    padding:10px 14px; font-family:inherit; font-size:11px; cursor:pointer; border-radius:2px;
    text-transform:uppercase; letter-spacing:.8px; transition:all .15s; }
  button:hover { background:#5b86c7; color:#fff; }
  .error { color:#f85149; font-size:12px; margin-top:12px; min-height:18px; }
  .pie { color:#6b748a; font-size:10px; text-align:center; margin-top:28px; padding-top:18px;
    border-top:1px solid #2a3343; }
</style>
</head>
<body>
  <form class="caja" method="POST">
    <h1>Silver<strong>Cloud</strong> Advisors</h1>
    <div class="linea">Acceso restringido</div>
    <label for="p">Contraseña</label>
    <input id="p" name="password" type="password" autofocus autocomplete="current-password">
    <button type="submit">Entrar</button>
    <div class="error">${conError ? 'Contraseña incorrecta.' : ''}</div>
    <div class="pie">Uso interno · CNV #474</div>
  </form>
</body>
</html>`;
}

function respuestaLogin(conError) {
  return new Response(pantallaLogin(conError), {
    status: conError ? 401 : 200,
    headers: {
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'no-store'
    }
  });
}

export async function onRequest(context) {
  const { request, env, next } = context;

  const clave = env.SC_PASSWORD;
  if (!clave) {
    return new Response('Falta configurar la variable SC_PASSWORD en Cloudflare Pages.',
      { status: 500 });
  }

  const esperado = await hash(clave);
  const cookies = request.headers.get('Cookie') || '';
  const autenticado = cookies.split(';')
    .map(c => c.trim())
    .includes(COOKIE + '=' + esperado);

  if (autenticado) return next();

  if (request.method === 'POST') {
    let enviada = '';
    try {
      const form = await request.formData();
      enviada = form.get('password') || '';
    } catch (e) { /* cuerpo inválido: se trata como intento fallido */ }

    if (await hash(enviada) === esperado) {
      const url = new URL(request.url);
      return new Response(null, {
        status: 303,
        headers: {
          'Location': url.pathname + url.search,
          'Set-Cookie': COOKIE + '=' + esperado + '; Path=/; HttpOnly; Secure; SameSite=Lax' +
            '; Max-Age=' + (60 * 60 * 24 * DIAS),
          'Cache-Control': 'no-store'
        }
      });
    }
    return respuestaLogin(true);
  }

  return respuestaLogin(false);
}
