-- Nota: hashare le password nell'app (es. bcrypt) prima di inserirle in questa tabella.

BEGIN;

-- 1) Tabella CLIENTE
CREATE TABLE IF NOT EXISTS CLIENTE (
  ID_CLIENTE SERIAL PRIMARY KEY,
  NOME VARCHAR(50) NOT NULL,
  COGNOME VARCHAR(50) NOT NULL,
  MATRICOLA INT UNIQUE,
  EMAIL VARCHAR(100) UNIQUE NOT NULL,
  PASSWORD VARCHAR(255) NOT NULL,
  ATTIVO BOOLEAN DEFAULT TRUE,
  CONSTRAINT chk_email_non_empty CHECK (EMAIL <> '')
);

-- 2) Tabella ALLERGIA
CREATE TABLE IF NOT EXISTS ALLERGIA (
  ID_ALLERGIA SERIAL PRIMARY KEY,
  NOME_ALLERGIA VARCHAR(50) UNIQUE NOT NULL
);

-- 3) Tabella ARTICOLO
CREATE TABLE IF NOT EXISTS ARTICOLO (
  ID_ARTICOLO SERIAL PRIMARY KEY,
  NOME_ARTICOLO VARCHAR(100) NOT NULL,
  DESCRIZIONE TEXT,
  PREZZO NUMERIC(8,2) NOT NULL CHECK (PREZZO >= 0)
);

-- 4) Tabella ARTICOLO_ALLERGIA (M:N)
CREATE TABLE IF NOT EXISTS ARTICOLO_ALLERGIA (
  ID_ARTICOLO INT NOT NULL REFERENCES ARTICOLO(ID_ARTICOLO) ON DELETE CASCADE,
  ID_ALLERGIA INT NOT NULL REFERENCES ALLERGIA(ID_ALLERGIA) ON DELETE CASCADE,
  PRIMARY KEY (ID_ARTICOLO, ID_ALLERGIA)
);

-- 5) Tabella CLIENTE_ALLERGIA (M:N)
CREATE TABLE IF NOT EXISTS CLIENTE_ALLERGIA (
  ID_CLIENTE INT NOT NULL REFERENCES CLIENTE(ID_CLIENTE) ON DELETE CASCADE,
  ID_ALLERGIA INT NOT NULL REFERENCES ALLERGIA(ID_ALLERGIA) ON DELETE CASCADE,
  PRIMARY KEY (ID_CLIENTE, ID_ALLERGIA)
);

-- 6) Tabella ORDINE
CREATE TABLE IF NOT EXISTS ORDINE (
  ID_ORDINE SERIAL PRIMARY KEY,
  ID_CLIENTE INT REFERENCES CLIENTE(ID_CLIENTE) ON DELETE SET NULL,
  DATA_ORDINE TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
  CONFERMATO BOOLEAN DEFAULT FALSE,
  NOTE TEXT
);

-- 7) Tabella DETTAGLIO_ORDINE
CREATE TABLE IF NOT EXISTS DETTAGLIO_ORDINE (
  ID_ORDINE INT NOT NULL REFERENCES ORDINE(ID_ORDINE) ON DELETE CASCADE,
  ID_ARTICOLO INT NOT NULL REFERENCES ARTICOLO(ID_ARTICOLO) ON DELETE RESTRICT,
  QUANTITA INT NOT NULL DEFAULT 1 CHECK (QUANTITA > 0),
  PREZZO_UNITARIO NUMERIC(8,2) NOT NULL CHECK (PREZZO_UNITARIO >= 0),
  PRIMARY KEY (ID_ORDINE, ID_ARTICOLO)
);

-- Indici utili
CREATE INDEX IF NOT EXISTS idx_ordine_id_cliente ON ORDINE(ID_CLIENTE);
CREATE INDEX IF NOT EXISTS idx_dettaglio_id_articolo ON DETTAGLIO_ORDINE(ID_ARTICOLO);

-- Popolamento iniziale - alcuni allergeni comuni
INSERT INTO ALLERGIA (NOME_ALLERGIA) VALUES
  ('GLUTINE'),
  ('LATTE'),
  ('UOVA'),
  ('FRUTTA A GUSCIO'),
  ('SOIA'),
  ('CROSTACEI')
ON CONFLICT (NOME_ALLERGIA) DO NOTHING;

-- Esempio: inserimento di articoli con prezzo
INSERT INTO ARTICOLO (NOME_ARTICOLO, DESCRIZIONE, PREZZO) VALUES
  ('Panino Prosciutto e Formaggio', 'Panino caldo con prosciutto cotto e formaggio', 4.50),
  ('Insalata Mista', 'Insalata fresca con pomodori, lattuga e carote', 3.80),
  ('Lasagna', 'Lasagna tradizionale al ragù', 6.50)
ON CONFLICT DO NOTHING;

-- Esempio: associare allergie agli articoli (usare gli ID corretti dopo il popolamento reale)
-- Qui assumiamo che le allergie e gli articoli sopra siano state inserite col loro ID.
-- Per sicurezza usiamo INSERT ... SELECT per mappare per nome.

-- Associare "Lasagna" a GLUTINE e LATTE
INSERT INTO ARTICOLO_ALLERGIA (ID_ARTICOLO, ID_ALLERGIA)
SELECT a.ID_ARTICOLO, al.ID_ALLERGIA
FROM ARTICOLO a, ALLERGIA al
WHERE a.NOME_ARTICOLO = 'Lasagna' AND al.NOME_ALLERGIA IN ('GLUTINE', 'LATTE')
ON CONFLICT DO NOTHING;

-- Associare "Panino Prosciutto e Formaggio" a GLUTINE e LATTE
INSERT INTO ARTICOLO_ALLERGIA (ID_ARTICOLO, ID_ALLERGIA)
SELECT a.ID_ARTICOLO, al.ID_ALLERGIA
FROM ARTICOLO a, ALLERGIA al
WHERE a.NOME_ARTICOLO = 'Panino Prosciutto e Formaggio' AND al.NOME_ALLERGIA IN ('GLUTINE', 'LATTE')
ON CONFLICT DO NOTHING;

-- Esempio: creazione di un cliente (ATTENZIONE: usare hash per PASSWORD nell'app)
-- Qui inseriamo una password finta per scopo dimostrativo.
INSERT INTO CLIENTE (NOME, COGNOME, MATRICOLA, EMAIL, PASSWORD) VALUES
  ('Mario', 'Rossi', 12345, 'mario.rossi@example.com', 'PASSWORD_DA_HASHARE')
ON CONFLICT (EMAIL) DO NOTHING;

-- Associare allergie al cliente Mario (esempio: GLUTINE)
INSERT INTO CLIENTE_ALLERGIA (ID_CLIENTE, ID_ALLERGIA)
SELECT c.ID_CLIENTE, al.ID_ALLERGIA
FROM CLIENTE c, ALLERGIA al
WHERE c.EMAIL = 'mario.rossi@example.com' AND al.NOME_ALLERGIA = 'GLUTINE'
ON CONFLICT DO NOTHING;

COMMIT;

-- NOTE UTILI:
-- 1) Le password devono essere sempre hashed prima dell'inserimento (non memorizzare password plain).
-- 2) Quando crei un ordine, salva il PREZZO_UNITARIO in DETTAGLIO_ORDINE per preservare lo storico
--    (il prezzo dell'articolo potrebbe cambiare in futuro).
-- 3) Per filtrare gli articoli visibili a un cliente in base alle sue allergie, usa una query che escluda
--    gli articoli che hanno allergie in comune con il cliente (vedi esempio seguente).

-- Esempio di query: mostra gli articoli compatibili con il cliente con ID = :cliente_id
-- (sostituire :cliente_id con l'ID reale)
--
-- SELECT a.*
-- FROM ARTICOLO a
-- WHERE a.ID_ARTICOLO NOT IN (
--   SELECT aa.ID_ARTICOLO
--   FROM ARTICOLO_ALLERGIA aa
--   JOIN CLIENTE_ALLERGIA ca ON aa.ID_ALLERGIA = ca.ID_ALLERGIA
--   WHERE ca.ID_CLIENTE = :cliente_id
-- );

-- Esempio di inserimento di un ordine (procedura di massima):
-- 1) INSERT INTO ORDINE (ID_CLIENTE, NOTE) VALUES (:id_cliente, :note) RETURNING ID_ORDINE;
-- 2) Per ogni articolo: INSERT INTO DETTAGLIO_ORDINE (ID_ORDINE, ID_ARTICOLO, QUANTITA, PREZZO_UNITARIO)
--       VALUES (:id_ordine, :id_articolo, :quantita, :prezzo_unitario);
-- 3) Se pagamento effettuato, UPDATE ORDINE SET CONFERMATO = TRUE WHERE ID_ORDINE = :id_ordine;

-- Fine script
