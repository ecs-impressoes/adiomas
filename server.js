const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

const db = new sqlite3.Database('./database.db');
const JWT_SECRET = process.env.JWT_SECRET || 'idiomas_replit_2026_super_seguro';

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS usuarios (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nome TEXT NOT NULL,
    usuario TEXT UNIQUE NOT NULL,
    senha TEXT NOT NULL,
    tipo TEXT CHECK(tipo IN ('admin','aluno')) NOT NULL,
    idioma TEXT CHECK(idioma IN ('Inglês','Espanhol','Francês','Alemão')),
    criado_em DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS aulas (id INTEGER PRIMARY KEY, idioma TEXT NOT NULL, periodo TEXT NOT NULL, data TEXT NOT NULL, tema TEXT)`);
  db.run(`CREATE TABLE IF NOT EXISTS presencas (id INTEGER PRIMARY KEY, aula_id INT, aluno_id INT, presente INTEGER DEFAULT 0, UNIQUE(aula_id, aluno_id))`);
  db.run(`CREATE TABLE IF NOT EXISTS notas (id INTEGER PRIMARY KEY, aula_id INT, aluno_id INT, nota REAL, UNIQUE(aula_id, aluno_id))`);
  db.run(`CREATE TABLE IF NOT EXISTS atividades (id INTEGER PRIMARY KEY, aula_id INT, titulo TEXT NOT NULL, descricao TEXT)`);
  db.run(`CREATE TABLE IF NOT EXISTS atividades_status (id INTEGER PRIMARY KEY, atividade_id INT, aluno_id INT, concluida INTEGER DEFAULT 0, UNIQUE(atividade_id, aluno_id))`);
  db.run(`CREATE TABLE IF NOT EXISTS mensalidades (id INTEGER PRIMARY KEY, aluno_id INT, valor REAL NOT NULL, vencimento TEXT NOT NULL, status TEXT CHECK(status IN ('Pago','Pendente','Atrasado')) DEFAULT 'Pendente')`);

  db.get("SELECT * FROM usuarios WHERE tipo='admin'", async (err, row) => {
    if (!row) {
      const hash = await bcrypt.hash('admin123', 10);
      db.run("INSERT INTO usuarios (nome, usuario, senha, tipo) VALUES (?,?,?,?)", ['Admin', 'admin', hash, 'admin']);
    }
  });
});

const auth = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).json({error: 'Token ausente'});
  try { req.user = jwt.verify(token, JWT_SECRET); next(); } catch { res.status(401).json({error: 'Token inválido'}); }
};
const isAdmin = (req, res, next) => req.user.tipo === 'admin' ? next() : res.status(403).json({error: 'Só admin'});

app.post('/api/login', (req, res) => {
  db.get('SELECT * FROM usuarios WHERE usuario=?', [req.body.usuario], async (err, user) => {
    if (!user || !await bcrypt.compare(req.body.senha, user.senha)) return res.status(400).json({error: 'Login inválido'});
    const token = jwt.sign({ id: user.id, tipo: user.tipo }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, nome: user.nome, tipo: user.tipo, id: user.id, idioma: user.idioma });
  });
});

app.get('/api/alunos', auth, isAdmin, (req, res) => {
  db.all("SELECT id, nome, usuario, idioma FROM usuarios WHERE tipo='aluno' ORDER BY nome", [], (err, rows) => res.json(rows));
});

app.post('/api/alunos', auth, isAdmin, (req, res) => {
  bcrypt.hash(req.body.senha, 10).then(hash => {
    db.run('INSERT INTO usuarios (nome, usuario, senha, tipo, idioma) VALUES (?,?,?,?,?)',
      [req.body.nome, req.body.usuario, hash, 'aluno', req.body.idioma], function(err) {
        if (err) return res.status(400).json({error: 'Usuário já existe ou limite atingido'});
        res.json({ok: true, id: this.lastID});
      });
  });
});

app.get('/api/aulas', auth, (req, res) => {
  db.all('SELECT * FROM aulas ORDER BY data DESC', [], (err, rows) => res.json(rows));
});

app.post('/api/aulas', auth, isAdmin, (req, res) => {
  db.run('INSERT INTO aulas (idioma, periodo, data, tema) VALUES (?,?,?,?)',
    [req.body.idioma, req.body.periodo, req.body.data, req.body.tema], function() { res.json({id: this.lastID}); });
});

app.post('/api/presenca', auth, isAdmin, (req, res) => {
  const stmt = db.prepare(`INSERT INTO presencas (aula_id, aluno_id, presente) VALUES (?,?,?) ON CONFLICT DO UPDATE SET presente=excluded.presente`);
  req.body.presencas.forEach(p => stmt.run(req.body.aula_id, p.aluno_id, p.presente ? 1 : 0));
  stmt.finalize(); res.json({ok: true});
});

app.post('/api/notas', auth, isAdmin, (req, res) => {
  const stmt = db.prepare(`INSERT INTO notas (aula_id, aluno_id, nota) VALUES (?,?,?) ON CONFLICT DO UPDATE SET nota=excluded.nota`);
  req.body.notas.forEach(n => stmt.run(req.body.aula_id, n.aluno_id, n.nota));
  stmt.finalize(); res.json({ok: true});
});

app.get('/api/desempenho/:aluno_id', auth, (req, res) => {
  const id = req.params.aluno_id;
  if (req.user.tipo !== 'admin' && req.user.id != id) return res.status(403).json({error: 'Sem permissão'});
  db.all(`SELECT a.periodo, AVG(n.nota) as media, COUNT(p.id) as total, SUM(p.presente) as presencas FROM aulas a
          LEFT JOIN notas n ON n.aula_id=a.id AND n.aluno_id=?
          LEFT JOIN presencas p ON p.aula_id=a.id AND p.aluno_id=?
          GROUP BY a.periodo`, [id, id], (err, rows) => res.json(rows));
});

app.post('/api/atividades', auth, isAdmin, (req, res) => {
  db.run('INSERT INTO atividades (aula_id, titulo, descricao) VALUES (?,?,?)',
    [req.body.aula_id, req.body.titulo, req.body.descricao], function() { res.json({id: this.lastID}); });
});

app.get('/api/atividades/:idioma', auth, (req, res) => {
  db.all(`SELECT at.* FROM atividades at JOIN aulas a ON at.aula_id=a.id WHERE a.idioma=?`, [req.params.idioma], (err, rows) => res.json(rows));
});

app.post('/api/mensalidades', auth, isAdmin, (req, res) => {
  db.run('INSERT INTO mensalidades (aluno_id, valor, vencimento, status) VALUES (?,?,?,?)',
    [req.body.aluno_id, req.body.valor, req.body.vencimento, req.body.status], () => res.json({ok: true}));
});

app.get('/api/financeiro', auth, isAdmin, (req, res) => {
  db.get(`SELECT SUM(CASE WHEN status='Pago' THEN valor ELSE 0 END) as recebido,
          SUM(CASE WHEN status='Pendente' THEN valor ELSE 0 END) as a_receber,
          SUM(CASE WHEN status='Atrasado' THEN valor ELSE 0 END) as inadimplencia FROM mensalidades`, [], (err, row) => res.json(row));
});

app.get('/api/mensalidades/:aluno_id', auth, (req, res) => {
  const id = req.params.aluno_id;
  if (req.user.tipo !== 'admin' && req.user.id != id) return res.status(403).json({error: 'Sem permissão'});
  db.all('SELECT * FROM mensalidades WHERE aluno_id=? ORDER BY vencimento DESC', [id], (err, rows) => res.json(rows));
});

app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log('Sistema rodando na porta', PORT));
