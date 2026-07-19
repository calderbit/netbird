package conntype

import (
	"fmt"
)

const (
	None           ConnPriority = 0
	Relay          ConnPriority = 1
	ICETurn        ConnPriority = 2
	SCION          ConnPriority = 3
	ICEP2P         ConnPriority = 4
	SCIONPreferred ConnPriority = 5
)

type ConnPriority int

func (cp ConnPriority) String() string {
	switch cp {
	case None:
		return "None"
	case Relay:
		return "PriorityRelay"
	case ICETurn:
		return "PriorityICETurn"
	case SCION, SCIONPreferred:
		return "PrioritySCION"
	case ICEP2P:
		return "PriorityICEP2P"
	default:
		return fmt.Sprintf("ConnPriority(%d)", cp)
	}
}
