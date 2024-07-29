package internal

import "errors"

var (
	// ErrInvalidParameters indicates that wrong input has been provided.
	ErrInvalidParameters = errors.New("invalid parameters")

	// ErrInvalidCiphersuite indicates a non-supported ciphersuite is being used.
	ErrInvalidCiphersuite = errors.New("ciphersuite not available")

	// ErrInvalidParticipantBackup indicates the participant's encoded backup is not valid.
	ErrInvalidParticipantBackup = errors.New("invalid backup")

	// ErrInvalidLength indicates that a provided encoded data piece is not of the expected length.
	ErrInvalidLength = errors.New("invalid encoding length")

	ErrWrongVerificationData = errors.New("the commitment and signature share don't belong the same participant")

	ErrInvalidVerificationShare = errors.New("signature share does not not match")
)
