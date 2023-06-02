// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.30.0
// 	protoc        v3.21.12
// source: keeper.proto

package proto

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// Represent the data required for user registration or authentification.
type AuthDataRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Login    string `protobuf:"bytes,1,opt,name=login,proto3" json:"login,omitempty"`
	Password string `protobuf:"bytes,2,opt,name=password,proto3" json:"password,omitempty"`
}

func (x *AuthDataRequest) Reset() {
	*x = AuthDataRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_keeper_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *AuthDataRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AuthDataRequest) ProtoMessage() {}

func (x *AuthDataRequest) ProtoReflect() protoreflect.Message {
	mi := &file_keeper_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AuthDataRequest.ProtoReflect.Descriptor instead.
func (*AuthDataRequest) Descriptor() ([]byte, []int) {
	return file_keeper_proto_rawDescGZIP(), []int{0}
}

func (x *AuthDataRequest) GetLogin() string {
	if x != nil {
		return x.Login
	}
	return ""
}

func (x *AuthDataRequest) GetPassword() string {
	if x != nil {
		return x.Password
	}
	return ""
}

// Represent the data which client get after success registration or authentification.
type AuthTokenResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Token string `protobuf:"bytes,1,opt,name=token,proto3" json:"token,omitempty"`
}

func (x *AuthTokenResponse) Reset() {
	*x = AuthTokenResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_keeper_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *AuthTokenResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AuthTokenResponse) ProtoMessage() {}

func (x *AuthTokenResponse) ProtoReflect() protoreflect.Message {
	mi := &file_keeper_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AuthTokenResponse.ProtoReflect.Descriptor instead.
func (*AuthTokenResponse) Descriptor() ([]byte, []int) {
	return file_keeper_proto_rawDescGZIP(), []int{1}
}

func (x *AuthTokenResponse) GetToken() string {
	if x != nil {
		return x.Token
	}
	return ""
}

// Represent chest data.
type Chest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Id        string  `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
	UserId    *string `protobuf:"bytes,2,opt,name=user_id,json=userId,proto3,oneof" json:"user_id,omitempty"`
	Salt      []byte  `protobuf:"bytes,3,opt,name=salt,proto3" json:"salt,omitempty"`
	Name      string  `protobuf:"bytes,4,opt,name=name,proto3" json:"name,omitempty"`
	Data      []byte  `protobuf:"bytes,5,opt,name=data,proto3" json:"data,omitempty"`
	DatatType int32   `protobuf:"varint,6,opt,name=datat_type,json=datatType,proto3" json:"datat_type,omitempty"`
}

func (x *Chest) Reset() {
	*x = Chest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_keeper_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Chest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Chest) ProtoMessage() {}

func (x *Chest) ProtoReflect() protoreflect.Message {
	mi := &file_keeper_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Chest.ProtoReflect.Descriptor instead.
func (*Chest) Descriptor() ([]byte, []int) {
	return file_keeper_proto_rawDescGZIP(), []int{2}
}

func (x *Chest) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

func (x *Chest) GetUserId() string {
	if x != nil && x.UserId != nil {
		return *x.UserId
	}
	return ""
}

func (x *Chest) GetSalt() []byte {
	if x != nil {
		return x.Salt
	}
	return nil
}

func (x *Chest) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *Chest) GetData() []byte {
	if x != nil {
		return x.Data
	}
	return nil
}

func (x *Chest) GetDatatType() int32 {
	if x != nil {
		return x.DatatType
	}
	return 0
}

// Represent history data.
type History struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Id            string  `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
	ChestId       string  `protobuf:"bytes,2,opt,name=chest_id,json=chestId,proto3" json:"chest_id,omitempty"`
	UserId        *string `protobuf:"bytes,3,opt,name=user_id,json=userId,proto3,oneof" json:"user_id,omitempty"`
	OperationType int32   `protobuf:"varint,4,opt,name=operation_type,json=operationType,proto3" json:"operation_type,omitempty"`
	OperationTime int64   `protobuf:"varint,5,opt,name=operation_time,json=operationTime,proto3" json:"operation_time,omitempty"`
	SyncingTime   *int64  `protobuf:"varint,6,opt,name=syncing_time,json=syncingTime,proto3,oneof" json:"syncing_time,omitempty"`
	DeviceName    string  `protobuf:"bytes,7,opt,name=device_name,json=deviceName,proto3" json:"device_name,omitempty"`
	DeviceIp      *string `protobuf:"bytes,8,opt,name=device_ip,json=deviceIp,proto3,oneof" json:"device_ip,omitempty"`
}

func (x *History) Reset() {
	*x = History{}
	if protoimpl.UnsafeEnabled {
		mi := &file_keeper_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *History) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*History) ProtoMessage() {}

func (x *History) ProtoReflect() protoreflect.Message {
	mi := &file_keeper_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use History.ProtoReflect.Descriptor instead.
func (*History) Descriptor() ([]byte, []int) {
	return file_keeper_proto_rawDescGZIP(), []int{3}
}

func (x *History) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

func (x *History) GetChestId() string {
	if x != nil {
		return x.ChestId
	}
	return ""
}

func (x *History) GetUserId() string {
	if x != nil && x.UserId != nil {
		return *x.UserId
	}
	return ""
}

func (x *History) GetOperationType() int32 {
	if x != nil {
		return x.OperationType
	}
	return 0
}

func (x *History) GetOperationTime() int64 {
	if x != nil {
		return x.OperationTime
	}
	return 0
}

func (x *History) GetSyncingTime() int64 {
	if x != nil && x.SyncingTime != nil {
		return *x.SyncingTime
	}
	return 0
}

func (x *History) GetDeviceName() string {
	if x != nil {
		return x.DeviceName
	}
	return ""
}

func (x *History) GetDeviceIp() string {
	if x != nil && x.DeviceIp != nil {
		return *x.DeviceIp
	}
	return ""
}

// Represent the transfered data when get chest by id.
type ChestIDRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	ChestId string `protobuf:"bytes,1,opt,name=chest_id,json=chestId,proto3" json:"chest_id,omitempty"`
}

func (x *ChestIDRequest) Reset() {
	*x = ChestIDRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_keeper_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ChestIDRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ChestIDRequest) ProtoMessage() {}

func (x *ChestIDRequest) ProtoReflect() protoreflect.Message {
	mi := &file_keeper_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ChestIDRequest.ProtoReflect.Descriptor instead.
func (*ChestIDRequest) Descriptor() ([]byte, []int) {
	return file_keeper_proto_rawDescGZIP(), []int{4}
}

func (x *ChestIDRequest) GetChestId() string {
	if x != nil {
		return x.ChestId
	}
	return ""
}

// Represent cehst response.
type ChestResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Chest   *Chest   `protobuf:"bytes,1,opt,name=chest,proto3" json:"chest,omitempty"`
	History *History `protobuf:"bytes,2,opt,name=history,proto3" json:"history,omitempty"`
}

func (x *ChestResponse) Reset() {
	*x = ChestResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_keeper_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ChestResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ChestResponse) ProtoMessage() {}

func (x *ChestResponse) ProtoReflect() protoreflect.Message {
	mi := &file_keeper_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ChestResponse.ProtoReflect.Descriptor instead.
func (*ChestResponse) Descriptor() ([]byte, []int) {
	return file_keeper_proto_rawDescGZIP(), []int{5}
}

func (x *ChestResponse) GetChest() *Chest {
	if x != nil {
		return x.Chest
	}
	return nil
}

func (x *ChestResponse) GetHistory() *History {
	if x != nil {
		return x.History
	}
	return nil
}

// Represent data for chest creation/modifing requests.
type ChestRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Chest   *Chest   `protobuf:"bytes,1,opt,name=chest,proto3" json:"chest,omitempty"`
	History *History `protobuf:"bytes,2,opt,name=history,proto3" json:"history,omitempty"`
}

func (x *ChestRequest) Reset() {
	*x = ChestRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_keeper_proto_msgTypes[6]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ChestRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ChestRequest) ProtoMessage() {}

func (x *ChestRequest) ProtoReflect() protoreflect.Message {
	mi := &file_keeper_proto_msgTypes[6]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ChestRequest.ProtoReflect.Descriptor instead.
func (*ChestRequest) Descriptor() ([]byte, []int) {
	return file_keeper_proto_rawDescGZIP(), []int{6}
}

func (x *ChestRequest) GetChest() *Chest {
	if x != nil {
		return x.Chest
	}
	return nil
}

func (x *ChestRequest) GetHistory() *History {
	if x != nil {
		return x.History
	}
	return nil
}

// Represent delete chest request.
type DeleteChestRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	History *History `protobuf:"bytes,1,opt,name=history,proto3" json:"history,omitempty"`
}

func (x *DeleteChestRequest) Reset() {
	*x = DeleteChestRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_keeper_proto_msgTypes[7]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DeleteChestRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DeleteChestRequest) ProtoMessage() {}

func (x *DeleteChestRequest) ProtoReflect() protoreflect.Message {
	mi := &file_keeper_proto_msgTypes[7]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DeleteChestRequest.ProtoReflect.Descriptor instead.
func (*DeleteChestRequest) Descriptor() ([]byte, []int) {
	return file_keeper_proto_rawDescGZIP(), []int{7}
}

func (x *DeleteChestRequest) GetHistory() *History {
	if x != nil {
		return x.History
	}
	return nil
}

// Represent respose as history event.
type HistoryResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	History *History `protobuf:"bytes,1,opt,name=history,proto3" json:"history,omitempty"`
}

func (x *HistoryResponse) Reset() {
	*x = HistoryResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_keeper_proto_msgTypes[8]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *HistoryResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*HistoryResponse) ProtoMessage() {}

func (x *HistoryResponse) ProtoReflect() protoreflect.Message {
	mi := &file_keeper_proto_msgTypes[8]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use HistoryResponse.ProtoReflect.Descriptor instead.
func (*HistoryResponse) Descriptor() ([]byte, []int) {
	return file_keeper_proto_rawDescGZIP(), []int{8}
}

func (x *HistoryResponse) GetHistory() *History {
	if x != nil {
		return x.History
	}
	return nil
}

// Represent sync request that contatins list of history events.
type SyncRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	History []*History `protobuf:"bytes,1,rep,name=history,proto3" json:"history,omitempty"`
}

func (x *SyncRequest) Reset() {
	*x = SyncRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_keeper_proto_msgTypes[9]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SyncRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SyncRequest) ProtoMessage() {}

func (x *SyncRequest) ProtoReflect() protoreflect.Message {
	mi := &file_keeper_proto_msgTypes[9]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SyncRequest.ProtoReflect.Descriptor instead.
func (*SyncRequest) Descriptor() ([]byte, []int) {
	return file_keeper_proto_rawDescGZIP(), []int{9}
}

func (x *SyncRequest) GetHistory() []*History {
	if x != nil {
		return x.History
	}
	return nil
}

// Represent sync response that contatins list of history events.
type SyncResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	History []*History `protobuf:"bytes,1,rep,name=history,proto3" json:"history,omitempty"`
}

func (x *SyncResponse) Reset() {
	*x = SyncResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_keeper_proto_msgTypes[10]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SyncResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SyncResponse) ProtoMessage() {}

func (x *SyncResponse) ProtoReflect() protoreflect.Message {
	mi := &file_keeper_proto_msgTypes[10]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SyncResponse.ProtoReflect.Descriptor instead.
func (*SyncResponse) Descriptor() ([]byte, []int) {
	return file_keeper_proto_rawDescGZIP(), []int{10}
}

func (x *SyncResponse) GetHistory() []*History {
	if x != nil {
		return x.History
	}
	return nil
}

var File_keeper_proto protoreflect.FileDescriptor

var file_keeper_proto_rawDesc = []byte{
	0x0a, 0x0c, 0x6b, 0x65, 0x65, 0x70, 0x65, 0x72, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x06,
	0x6b, 0x65, 0x65, 0x70, 0x65, 0x72, 0x22, 0x43, 0x0a, 0x0f, 0x41, 0x75, 0x74, 0x68, 0x44, 0x61,
	0x74, 0x61, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x14, 0x0a, 0x05, 0x6c, 0x6f, 0x67,
	0x69, 0x6e, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x6c, 0x6f, 0x67, 0x69, 0x6e, 0x12,
	0x1a, 0x0a, 0x08, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x08, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x22, 0x29, 0x0a, 0x11, 0x41,
	0x75, 0x74, 0x68, 0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65,
	0x12, 0x14, 0x0a, 0x05, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x05, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x22, 0x9c, 0x01, 0x0a, 0x05, 0x43, 0x68, 0x65, 0x73, 0x74,
	0x12, 0x0e, 0x0a, 0x02, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x02, 0x69, 0x64,
	0x12, 0x1c, 0x0a, 0x07, 0x75, 0x73, 0x65, 0x72, 0x5f, 0x69, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28,
	0x09, 0x48, 0x00, 0x52, 0x06, 0x75, 0x73, 0x65, 0x72, 0x49, 0x64, 0x88, 0x01, 0x01, 0x12, 0x12,
	0x0a, 0x04, 0x73, 0x61, 0x6c, 0x74, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x04, 0x73, 0x61,
	0x6c, 0x74, 0x12, 0x12, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x04, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x12, 0x0a, 0x04, 0x64, 0x61, 0x74, 0x61, 0x18, 0x05,
	0x20, 0x01, 0x28, 0x0c, 0x52, 0x04, 0x64, 0x61, 0x74, 0x61, 0x12, 0x1d, 0x0a, 0x0a, 0x64, 0x61,
	0x74, 0x61, 0x74, 0x5f, 0x74, 0x79, 0x70, 0x65, 0x18, 0x06, 0x20, 0x01, 0x28, 0x05, 0x52, 0x09,
	0x64, 0x61, 0x74, 0x61, 0x74, 0x54, 0x79, 0x70, 0x65, 0x42, 0x0a, 0x0a, 0x08, 0x5f, 0x75, 0x73,
	0x65, 0x72, 0x5f, 0x69, 0x64, 0x22, 0xb6, 0x02, 0x0a, 0x07, 0x48, 0x69, 0x73, 0x74, 0x6f, 0x72,
	0x79, 0x12, 0x0e, 0x0a, 0x02, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x02, 0x69,
	0x64, 0x12, 0x19, 0x0a, 0x08, 0x63, 0x68, 0x65, 0x73, 0x74, 0x5f, 0x69, 0x64, 0x18, 0x02, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x07, 0x63, 0x68, 0x65, 0x73, 0x74, 0x49, 0x64, 0x12, 0x1c, 0x0a, 0x07,
	0x75, 0x73, 0x65, 0x72, 0x5f, 0x69, 0x64, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x48, 0x00, 0x52,
	0x06, 0x75, 0x73, 0x65, 0x72, 0x49, 0x64, 0x88, 0x01, 0x01, 0x12, 0x25, 0x0a, 0x0e, 0x6f, 0x70,
	0x65, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x74, 0x79, 0x70, 0x65, 0x18, 0x04, 0x20, 0x01,
	0x28, 0x05, 0x52, 0x0d, 0x6f, 0x70, 0x65, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x54, 0x79, 0x70,
	0x65, 0x12, 0x25, 0x0a, 0x0e, 0x6f, 0x70, 0x65, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x74,
	0x69, 0x6d, 0x65, 0x18, 0x05, 0x20, 0x01, 0x28, 0x03, 0x52, 0x0d, 0x6f, 0x70, 0x65, 0x72, 0x61,
	0x74, 0x69, 0x6f, 0x6e, 0x54, 0x69, 0x6d, 0x65, 0x12, 0x26, 0x0a, 0x0c, 0x73, 0x79, 0x6e, 0x63,
	0x69, 0x6e, 0x67, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x18, 0x06, 0x20, 0x01, 0x28, 0x03, 0x48, 0x01,
	0x52, 0x0b, 0x73, 0x79, 0x6e, 0x63, 0x69, 0x6e, 0x67, 0x54, 0x69, 0x6d, 0x65, 0x88, 0x01, 0x01,
	0x12, 0x1f, 0x0a, 0x0b, 0x64, 0x65, 0x76, 0x69, 0x63, 0x65, 0x5f, 0x6e, 0x61, 0x6d, 0x65, 0x18,
	0x07, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0a, 0x64, 0x65, 0x76, 0x69, 0x63, 0x65, 0x4e, 0x61, 0x6d,
	0x65, 0x12, 0x20, 0x0a, 0x09, 0x64, 0x65, 0x76, 0x69, 0x63, 0x65, 0x5f, 0x69, 0x70, 0x18, 0x08,
	0x20, 0x01, 0x28, 0x09, 0x48, 0x02, 0x52, 0x08, 0x64, 0x65, 0x76, 0x69, 0x63, 0x65, 0x49, 0x70,
	0x88, 0x01, 0x01, 0x42, 0x0a, 0x0a, 0x08, 0x5f, 0x75, 0x73, 0x65, 0x72, 0x5f, 0x69, 0x64, 0x42,
	0x0f, 0x0a, 0x0d, 0x5f, 0x73, 0x79, 0x6e, 0x63, 0x69, 0x6e, 0x67, 0x5f, 0x74, 0x69, 0x6d, 0x65,
	0x42, 0x0c, 0x0a, 0x0a, 0x5f, 0x64, 0x65, 0x76, 0x69, 0x63, 0x65, 0x5f, 0x69, 0x70, 0x22, 0x2b,
	0x0a, 0x0e, 0x43, 0x68, 0x65, 0x73, 0x74, 0x49, 0x44, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74,
	0x12, 0x19, 0x0a, 0x08, 0x63, 0x68, 0x65, 0x73, 0x74, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x07, 0x63, 0x68, 0x65, 0x73, 0x74, 0x49, 0x64, 0x22, 0x5f, 0x0a, 0x0d, 0x43,
	0x68, 0x65, 0x73, 0x74, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x23, 0x0a, 0x05,
	0x63, 0x68, 0x65, 0x73, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x0d, 0x2e, 0x6b, 0x65,
	0x65, 0x70, 0x65, 0x72, 0x2e, 0x43, 0x68, 0x65, 0x73, 0x74, 0x52, 0x05, 0x63, 0x68, 0x65, 0x73,
	0x74, 0x12, 0x29, 0x0a, 0x07, 0x68, 0x69, 0x73, 0x74, 0x6f, 0x72, 0x79, 0x18, 0x02, 0x20, 0x01,
	0x28, 0x0b, 0x32, 0x0f, 0x2e, 0x6b, 0x65, 0x65, 0x70, 0x65, 0x72, 0x2e, 0x48, 0x69, 0x73, 0x74,
	0x6f, 0x72, 0x79, 0x52, 0x07, 0x68, 0x69, 0x73, 0x74, 0x6f, 0x72, 0x79, 0x22, 0x5e, 0x0a, 0x0c,
	0x43, 0x68, 0x65, 0x73, 0x74, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x23, 0x0a, 0x05,
	0x63, 0x68, 0x65, 0x73, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x0d, 0x2e, 0x6b, 0x65,
	0x65, 0x70, 0x65, 0x72, 0x2e, 0x43, 0x68, 0x65, 0x73, 0x74, 0x52, 0x05, 0x63, 0x68, 0x65, 0x73,
	0x74, 0x12, 0x29, 0x0a, 0x07, 0x68, 0x69, 0x73, 0x74, 0x6f, 0x72, 0x79, 0x18, 0x02, 0x20, 0x01,
	0x28, 0x0b, 0x32, 0x0f, 0x2e, 0x6b, 0x65, 0x65, 0x70, 0x65, 0x72, 0x2e, 0x48, 0x69, 0x73, 0x74,
	0x6f, 0x72, 0x79, 0x52, 0x07, 0x68, 0x69, 0x73, 0x74, 0x6f, 0x72, 0x79, 0x22, 0x3f, 0x0a, 0x12,
	0x44, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x43, 0x68, 0x65, 0x73, 0x74, 0x52, 0x65, 0x71, 0x75, 0x65,
	0x73, 0x74, 0x12, 0x29, 0x0a, 0x07, 0x68, 0x69, 0x73, 0x74, 0x6f, 0x72, 0x79, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x0b, 0x32, 0x0f, 0x2e, 0x6b, 0x65, 0x65, 0x70, 0x65, 0x72, 0x2e, 0x48, 0x69, 0x73,
	0x74, 0x6f, 0x72, 0x79, 0x52, 0x07, 0x68, 0x69, 0x73, 0x74, 0x6f, 0x72, 0x79, 0x22, 0x3c, 0x0a,
	0x0f, 0x48, 0x69, 0x73, 0x74, 0x6f, 0x72, 0x79, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65,
	0x12, 0x29, 0x0a, 0x07, 0x68, 0x69, 0x73, 0x74, 0x6f, 0x72, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x0b, 0x32, 0x0f, 0x2e, 0x6b, 0x65, 0x65, 0x70, 0x65, 0x72, 0x2e, 0x48, 0x69, 0x73, 0x74, 0x6f,
	0x72, 0x79, 0x52, 0x07, 0x68, 0x69, 0x73, 0x74, 0x6f, 0x72, 0x79, 0x22, 0x38, 0x0a, 0x0b, 0x53,
	0x79, 0x6e, 0x63, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x29, 0x0a, 0x07, 0x68, 0x69,
	0x73, 0x74, 0x6f, 0x72, 0x79, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x0f, 0x2e, 0x6b, 0x65,
	0x65, 0x70, 0x65, 0x72, 0x2e, 0x48, 0x69, 0x73, 0x74, 0x6f, 0x72, 0x79, 0x52, 0x07, 0x68, 0x69,
	0x73, 0x74, 0x6f, 0x72, 0x79, 0x22, 0x39, 0x0a, 0x0c, 0x53, 0x79, 0x6e, 0x63, 0x52, 0x65, 0x73,
	0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x29, 0x0a, 0x07, 0x68, 0x69, 0x73, 0x74, 0x6f, 0x72, 0x79,
	0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x0f, 0x2e, 0x6b, 0x65, 0x65, 0x70, 0x65, 0x72, 0x2e,
	0x48, 0x69, 0x73, 0x74, 0x6f, 0x72, 0x79, 0x52, 0x07, 0x68, 0x69, 0x73, 0x74, 0x6f, 0x72, 0x79,
	0x32, 0xb3, 0x03, 0x0a, 0x06, 0x4b, 0x65, 0x65, 0x70, 0x65, 0x72, 0x12, 0x3c, 0x0a, 0x06, 0x53,
	0x69, 0x67, 0x6e, 0x55, 0x70, 0x12, 0x17, 0x2e, 0x6b, 0x65, 0x65, 0x70, 0x65, 0x72, 0x2e, 0x41,
	0x75, 0x74, 0x68, 0x44, 0x61, 0x74, 0x61, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x19,
	0x2e, 0x6b, 0x65, 0x65, 0x70, 0x65, 0x72, 0x2e, 0x41, 0x75, 0x74, 0x68, 0x54, 0x6f, 0x6b, 0x65,
	0x6e, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x3c, 0x0a, 0x06, 0x53, 0x69, 0x67,
	0x6e, 0x49, 0x6e, 0x12, 0x17, 0x2e, 0x6b, 0x65, 0x65, 0x70, 0x65, 0x72, 0x2e, 0x41, 0x75, 0x74,
	0x68, 0x44, 0x61, 0x74, 0x61, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x19, 0x2e, 0x6b,
	0x65, 0x65, 0x70, 0x65, 0x72, 0x2e, 0x41, 0x75, 0x74, 0x68, 0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x52,
	0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x3d, 0x0a, 0x0c, 0x47, 0x65, 0x74, 0x43, 0x68,
	0x65, 0x73, 0x74, 0x42, 0x79, 0x49, 0x44, 0x12, 0x16, 0x2e, 0x6b, 0x65, 0x65, 0x70, 0x65, 0x72,
	0x2e, 0x43, 0x68, 0x65, 0x73, 0x74, 0x49, 0x44, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a,
	0x15, 0x2e, 0x6b, 0x65, 0x65, 0x70, 0x65, 0x72, 0x2e, 0x43, 0x68, 0x65, 0x73, 0x74, 0x52, 0x65,
	0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x39, 0x0a, 0x08, 0x41, 0x64, 0x64, 0x43, 0x68, 0x65,
	0x73, 0x74, 0x12, 0x14, 0x2e, 0x6b, 0x65, 0x65, 0x70, 0x65, 0x72, 0x2e, 0x43, 0x68, 0x65, 0x73,
	0x74, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x17, 0x2e, 0x6b, 0x65, 0x65, 0x70, 0x65,
	0x72, 0x2e, 0x48, 0x69, 0x73, 0x74, 0x6f, 0x72, 0x79, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73,
	0x65, 0x12, 0x3c, 0x0a, 0x0b, 0x55, 0x70, 0x64, 0x61, 0x74, 0x65, 0x43, 0x68, 0x65, 0x73, 0x74,
	0x12, 0x14, 0x2e, 0x6b, 0x65, 0x65, 0x70, 0x65, 0x72, 0x2e, 0x43, 0x68, 0x65, 0x73, 0x74, 0x52,
	0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x17, 0x2e, 0x6b, 0x65, 0x65, 0x70, 0x65, 0x72, 0x2e,
	0x48, 0x69, 0x73, 0x74, 0x6f, 0x72, 0x79, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12,
	0x42, 0x0a, 0x0b, 0x44, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x43, 0x68, 0x65, 0x73, 0x74, 0x12, 0x1a,
	0x2e, 0x6b, 0x65, 0x65, 0x70, 0x65, 0x72, 0x2e, 0x44, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x43, 0x68,
	0x65, 0x73, 0x74, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x17, 0x2e, 0x6b, 0x65, 0x65,
	0x70, 0x65, 0x72, 0x2e, 0x48, 0x69, 0x73, 0x74, 0x6f, 0x72, 0x79, 0x52, 0x65, 0x73, 0x70, 0x6f,
	0x6e, 0x73, 0x65, 0x12, 0x31, 0x0a, 0x04, 0x53, 0x79, 0x6e, 0x63, 0x12, 0x13, 0x2e, 0x6b, 0x65,
	0x65, 0x70, 0x65, 0x72, 0x2e, 0x53, 0x79, 0x6e, 0x63, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74,
	0x1a, 0x14, 0x2e, 0x6b, 0x65, 0x65, 0x70, 0x65, 0x72, 0x2e, 0x53, 0x79, 0x6e, 0x63, 0x52, 0x65,
	0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x42, 0x28, 0x5a, 0x26, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62,
	0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x50, 0x75, 0x65, 0x6e, 0x61, 0x2f, 0x70, 0x61, 0x73, 0x73, 0x77,
	0x6f, 0x72, 0x64, 0x2d, 0x6b, 0x65, 0x65, 0x70, 0x65, 0x72, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_keeper_proto_rawDescOnce sync.Once
	file_keeper_proto_rawDescData = file_keeper_proto_rawDesc
)

func file_keeper_proto_rawDescGZIP() []byte {
	file_keeper_proto_rawDescOnce.Do(func() {
		file_keeper_proto_rawDescData = protoimpl.X.CompressGZIP(file_keeper_proto_rawDescData)
	})
	return file_keeper_proto_rawDescData
}

var file_keeper_proto_msgTypes = make([]protoimpl.MessageInfo, 11)
var file_keeper_proto_goTypes = []interface{}{
	(*AuthDataRequest)(nil),    // 0: keeper.AuthDataRequest
	(*AuthTokenResponse)(nil),  // 1: keeper.AuthTokenResponse
	(*Chest)(nil),              // 2: keeper.Chest
	(*History)(nil),            // 3: keeper.History
	(*ChestIDRequest)(nil),     // 4: keeper.ChestIDRequest
	(*ChestResponse)(nil),      // 5: keeper.ChestResponse
	(*ChestRequest)(nil),       // 6: keeper.ChestRequest
	(*DeleteChestRequest)(nil), // 7: keeper.DeleteChestRequest
	(*HistoryResponse)(nil),    // 8: keeper.HistoryResponse
	(*SyncRequest)(nil),        // 9: keeper.SyncRequest
	(*SyncResponse)(nil),       // 10: keeper.SyncResponse
}
var file_keeper_proto_depIdxs = []int32{
	2,  // 0: keeper.ChestResponse.chest:type_name -> keeper.Chest
	3,  // 1: keeper.ChestResponse.history:type_name -> keeper.History
	2,  // 2: keeper.ChestRequest.chest:type_name -> keeper.Chest
	3,  // 3: keeper.ChestRequest.history:type_name -> keeper.History
	3,  // 4: keeper.DeleteChestRequest.history:type_name -> keeper.History
	3,  // 5: keeper.HistoryResponse.history:type_name -> keeper.History
	3,  // 6: keeper.SyncRequest.history:type_name -> keeper.History
	3,  // 7: keeper.SyncResponse.history:type_name -> keeper.History
	0,  // 8: keeper.Keeper.SignUp:input_type -> keeper.AuthDataRequest
	0,  // 9: keeper.Keeper.SignIn:input_type -> keeper.AuthDataRequest
	4,  // 10: keeper.Keeper.GetChestByID:input_type -> keeper.ChestIDRequest
	6,  // 11: keeper.Keeper.AddChest:input_type -> keeper.ChestRequest
	6,  // 12: keeper.Keeper.UpdateChest:input_type -> keeper.ChestRequest
	7,  // 13: keeper.Keeper.DeleteChest:input_type -> keeper.DeleteChestRequest
	9,  // 14: keeper.Keeper.Sync:input_type -> keeper.SyncRequest
	1,  // 15: keeper.Keeper.SignUp:output_type -> keeper.AuthTokenResponse
	1,  // 16: keeper.Keeper.SignIn:output_type -> keeper.AuthTokenResponse
	5,  // 17: keeper.Keeper.GetChestByID:output_type -> keeper.ChestResponse
	8,  // 18: keeper.Keeper.AddChest:output_type -> keeper.HistoryResponse
	8,  // 19: keeper.Keeper.UpdateChest:output_type -> keeper.HistoryResponse
	8,  // 20: keeper.Keeper.DeleteChest:output_type -> keeper.HistoryResponse
	10, // 21: keeper.Keeper.Sync:output_type -> keeper.SyncResponse
	15, // [15:22] is the sub-list for method output_type
	8,  // [8:15] is the sub-list for method input_type
	8,  // [8:8] is the sub-list for extension type_name
	8,  // [8:8] is the sub-list for extension extendee
	0,  // [0:8] is the sub-list for field type_name
}

func init() { file_keeper_proto_init() }
func file_keeper_proto_init() {
	if File_keeper_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_keeper_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*AuthDataRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_keeper_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*AuthTokenResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_keeper_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Chest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_keeper_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*History); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_keeper_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ChestIDRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_keeper_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ChestResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_keeper_proto_msgTypes[6].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ChestRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_keeper_proto_msgTypes[7].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*DeleteChestRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_keeper_proto_msgTypes[8].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*HistoryResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_keeper_proto_msgTypes[9].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SyncRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_keeper_proto_msgTypes[10].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SyncResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	file_keeper_proto_msgTypes[2].OneofWrappers = []interface{}{}
	file_keeper_proto_msgTypes[3].OneofWrappers = []interface{}{}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_keeper_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   11,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_keeper_proto_goTypes,
		DependencyIndexes: file_keeper_proto_depIdxs,
		MessageInfos:      file_keeper_proto_msgTypes,
	}.Build()
	File_keeper_proto = out.File
	file_keeper_proto_rawDesc = nil
	file_keeper_proto_goTypes = nil
	file_keeper_proto_depIdxs = nil
}
