package vote

import (
	"context"
	"time"

	wallet "github.com/ethereum/go-ethereum/accounts/bls"
	"github.com/ethereum/go-ethereum/params"

	"github.com/pkg/errors"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto/bls"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/metrics"
)

const (
	voteSignerTimeout = time.Second * 5
)

var votesSigningErrorCounter = metrics.NewRegisteredCounter("votesSigner/error", nil)

type VoteSigner struct {
	km     *wallet.KeyManager
	pubKey [params.BLSPubkeyLength]byte
}

func NewVoteSigner(blsPasswordPath, blsWalletPath string) (*VoteSigner, error) {
	w, err := wallet.New(blsWalletPath, blsPasswordPath)
	if err != nil {
		log.Error("Failed to open BLS wallet", "err", err)
		return nil, err
	}

	log.Info("Read BLS wallet password successfully")

	km, err := wallet.NewKeyManager(context.Background(), w)
	if err != nil {
		log.Error("Initialize key manager failed", "err", err)
		return nil, err
	}
	log.Info("Initialized keymanager successfully")

	ctx, cancel := context.WithTimeout(context.Background(), voteSignerTimeout)
	defer cancel()

	pubKeys, err := km.FetchValidatingPublicKeys(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "could not fetch validating public keys")
	}

	if len(pubKeys) < 1 {
		return nil, errors.New("no BLS key in keystore")
	}

	return &VoteSigner{
		km:     km,
		pubKey: pubKeys[0],
	}, nil
}

func (signer *VoteSigner) SignVote(vote *types.VoteEnvelope) error {
	// Sign the vote, fetch the first pubKey as validator's bls public key.
	pubKey := signer.pubKey
	blsPubKey, err := bls.PublicKeyFromBytes(pubKey[:])
	if err != nil {
		return errors.Wrap(err, "convert public key from bytes to bls failed")
	}

	voteDataHash := vote.Data.Hash()

	ctx, cancel := context.WithTimeout(context.Background(), voteSignerTimeout)
	defer cancel()

	signature, err := (*signer.km).Sign(ctx, &wallet.SignRequest{
		PublicKey:   pubKey[:],
		SigningRoot: voteDataHash[:],
	})
	if err != nil {
		return err
	}

	copy(vote.PublicKey[:], blsPubKey.Marshal()[:])
	copy(vote.Signature[:], signature.Marshal()[:])
	return nil
}
