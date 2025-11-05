async function main(){
  const base = 'http://localhost:3000';
  const j = (method, url, body, token) => fetch(url, { method, headers: { 'Content-Type': 'application/json', ...(token?{ Authorization: `Bearer ${token}` }: {}) }, body: body?JSON.stringify(body):undefined }).then(r=>r.json());
  try {
    console.log('--- /health');
    const h = await fetch(base + '/health').then(r=>r.text());
    console.log(h);

    console.log('--- register');
    const reg = await j('POST', base + '/api/auth/register', { username:'runner1', password:'P@ssw0rd!' });
    console.log(JSON.stringify(reg));

    console.log('--- login');
    const login = await j('POST', base + '/api/auth/login', { username:'runner1', password:'P@ssw0rd!' });
    console.log(JSON.stringify({ ok: login.success, user: login?.data?.user }));
    const token = login?.data?.token;
    if(!token){
      console.error('No token; login failed');
      process.exit(1);
    }

    console.log('--- /api/analytics/stats');
    const stats = await j('GET', base + '/api/analytics/stats', null, token);
    console.log(JSON.stringify(stats));

    console.log('SMOKE OK');
  } catch (e) {
    console.error('SMOKE FAILED', e);
    process.exit(1);
  }
}
main();
