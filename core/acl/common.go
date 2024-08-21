package acl

// ChACL - ACL channel name,
// CcACL - ACL chaincode name
const (
	ChACL = "acl"
	CcACL = "acl"
)

// acl chaincode functions
const (
	GetAccOpRightFn  = "getAccountOperationRight"
	AddRightsFn      = "addRights"
	AddUserFn        = "addUser"
	RemoveRightsFn   = "removeRights"
	AddUserArgsCount = 5
)
