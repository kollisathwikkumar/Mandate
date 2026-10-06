CREATE TABLE indexer_blocks (
  chain_id bigint NOT NULL CHECK (chain_id > 0),
  block_number bigint NOT NULL CHECK (block_number >= 0),
  block_hash char(66) NOT NULL,
  parent_hash char(66) NOT NULL,
  indexed_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (chain_id, block_number)
);

CREATE TABLE indexed_chain_logs (
  chain_id bigint NOT NULL CHECK (chain_id > 0),
  block_number bigint NOT NULL CHECK (block_number >= 0),
  block_hash char(66) NOT NULL,
  transaction_hash char(66) NOT NULL,
  transaction_index integer NOT NULL CHECK (transaction_index >= 0),
  log_index integer NOT NULL CHECK (log_index >= 0),
  address char(42) NOT NULL,
  topics text[] NOT NULL,
  data text NOT NULL,
  indexed_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (chain_id, block_hash, transaction_hash, log_index),
  FOREIGN KEY (chain_id, block_number) REFERENCES indexer_blocks(chain_id, block_number) ON DELETE CASCADE
);

CREATE INDEX indexed_chain_logs_address_height_idx
  ON indexed_chain_logs (chain_id, address, block_number, log_index);

CREATE INDEX indexed_chain_logs_transaction_idx
  ON indexed_chain_logs (chain_id, transaction_hash);
