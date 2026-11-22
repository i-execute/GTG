package client

import (
	"net"
	"strconv"

	"github.com/i-execute/GTG/session"
)

func ConfigFromAccount(account session.Account, apiID int, apiHash []byte) (Config, error) {
	if account.DCID <= 0 || len(account.AuthKey) != 256 || apiID <= 0 || len(apiHash) == 0 {
		return Config{}, ErrRPC
	}
	var endpoint session.DC
	found := false
	for _, candidate := range account.DCs {
		if candidate.ID == account.DCID && candidate.Address != "" && candidate.Port != 0 {
			endpoint = candidate
			found = true
			break
		}
	}
	if !found {
		return Config{}, ErrRPC
	}
	return Config{Endpoint: net.JoinHostPort(endpoint.Address, strconv.Itoa(int(endpoint.Port))), Transport: Intermediate, AuthKey: append([]byte(nil), account.AuthKey...), ServerSalt: account.ServerSalt, TimeOffset: account.TimeOffset, APIID: apiID, APIHash: append([]byte(nil), apiHash...), DeviceModel: "GTG", SystemVersion: "Go", AppVersion: "0.2-next", Language: "en"}, nil
}
