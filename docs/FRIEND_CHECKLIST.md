# Friend checklist

## A — Install (needs root)

```bash
cargo build
sudo bash scripts/install.sh
sudo systemctl enable --now dist-observe-collector
sudo systemctl enable --now dist-observe-agent@web-1
```

📋 SVCs `active (running)`?

## B — E2E (needs client cert)

```bash
curl --cacert CERT --cert CERT --key KEY https://HOST:18080/nodes
```

📋 Node listed with `skew_ok:true`?

## C — GPU box only (needs NVIDIA + driver)

```bash
nvidia-smi -L
./target/debug/dist-observe watch --interval 1 --count 5 --db /tmp/gpu-test.db
```

📋 GPU line shows real stats (not `no-gpu`)? If broken paste the exact line

## Cleanup

```bash
sudo systemctl disable --now dist-observe-collector 'dist-observe-agent@*'
```

Legend: SVC = service E2E = end to end
