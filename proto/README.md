# Protocol Documentation
<a name="top"></a>

## Table of Contents

- [keeper.proto](#keeper-proto)
    - [AuthDataRequest](#keeper-AuthDataRequest)
    - [AuthTokenResponse](#keeper-AuthTokenResponse)
    - [Chest](#keeper-Chest)
    - [ChestIDRequest](#keeper-ChestIDRequest)
    - [ChestRequest](#keeper-ChestRequest)
    - [ChestResponse](#keeper-ChestResponse)
    - [DeleteChestRequest](#keeper-DeleteChestRequest)
    - [History](#keeper-History)
    - [HistoryResponse](#keeper-HistoryResponse)
    - [SyncRequest](#keeper-SyncRequest)
    - [SyncResponse](#keeper-SyncResponse)
  
    - [Keeper](#keeper-Keeper)
  
- [keeper.proto](#keeper-proto)
    - [AuthDataRequest](#keeper-AuthDataRequest)
    - [AuthTokenResponse](#keeper-AuthTokenResponse)
    - [Chest](#keeper-Chest)
    - [ChestIDRequest](#keeper-ChestIDRequest)
    - [ChestRequest](#keeper-ChestRequest)
    - [ChestResponse](#keeper-ChestResponse)
    - [DeleteChestRequest](#keeper-DeleteChestRequest)
    - [History](#keeper-History)
    - [HistoryResponse](#keeper-HistoryResponse)
    - [SyncRequest](#keeper-SyncRequest)
    - [SyncResponse](#keeper-SyncResponse)
  
    - [Keeper](#keeper-Keeper)
  
- [Scalar Value Types](#scalar-value-types)



<a name="keeper-proto"></a>
<p align="right"><a href="#top">Top</a></p>

## keeper.proto



<a name="keeper-AuthDataRequest"></a>

### AuthDataRequest
Represent the data required for user registration or authentification.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| login | [string](#string) |  |  |
| password | [string](#string) |  |  |






<a name="keeper-AuthTokenResponse"></a>

### AuthTokenResponse
Represent the data which client get after success registration or authentification.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| token | [string](#string) |  |  |






<a name="keeper-Chest"></a>

### Chest
Represent chest data.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| id | [string](#string) |  |  |
| user_id | [string](#string) | optional |  |
| salt | [bytes](#bytes) |  |  |
| name | [string](#string) |  |  |
| data | [bytes](#bytes) |  |  |
| datat_type | [int32](#int32) |  |  |






<a name="keeper-ChestIDRequest"></a>

### ChestIDRequest
Represent the transfered data when get chest by id.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| chest_id | [string](#string) |  |  |






<a name="keeper-ChestRequest"></a>

### ChestRequest
Represent data for chest creation/modifing requests.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| chest | [Chest](#keeper-Chest) |  |  |
| history | [History](#keeper-History) |  |  |






<a name="keeper-ChestResponse"></a>

### ChestResponse
Represent cehst response.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| chest | [Chest](#keeper-Chest) |  |  |
| history | [History](#keeper-History) |  |  |






<a name="keeper-DeleteChestRequest"></a>

### DeleteChestRequest
Represent delete chest request.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| history | [History](#keeper-History) |  |  |






<a name="keeper-History"></a>

### History
Represent history data.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| id | [string](#string) |  |  |
| chest_id | [string](#string) |  |  |
| user_id | [string](#string) | optional |  |
| operation_type | [int32](#int32) |  |  |
| operation_time | [int64](#int64) |  |  |
| syncing_time | [int64](#int64) | optional |  |
| device_name | [string](#string) |  |  |
| device_ip | [string](#string) | optional |  |






<a name="keeper-HistoryResponse"></a>

### HistoryResponse
Represent respose as history event.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| history | [History](#keeper-History) |  |  |






<a name="keeper-SyncRequest"></a>

### SyncRequest
Represent sync request that contatins list of history events.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| history | [History](#keeper-History) | repeated |  |






<a name="keeper-SyncResponse"></a>

### SyncResponse
Represent sync response that contatins list of history events.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| history | [History](#keeper-History) | repeated |  |





 

 

 


<a name="keeper-Keeper"></a>

### Keeper
Service for handling keeper features.

| Method Name | Request Type | Response Type | Description |
| ----------- | ------------ | ------------- | ------------|
| SignUp | [AuthDataRequest](#keeper-AuthDataRequest) | [AuthTokenResponse](#keeper-AuthTokenResponse) | Handler for doing user registration. |
| SignIn | [AuthDataRequest](#keeper-AuthDataRequest) | [AuthTokenResponse](#keeper-AuthTokenResponse) | Handler for doing user authentification. |
| GetChestByID | [ChestIDRequest](#keeper-ChestIDRequest) | [ChestResponse](#keeper-ChestResponse) | Handler for getting chest by id. |
| AddChest | [ChestRequest](#keeper-ChestRequest) | [HistoryResponse](#keeper-HistoryResponse) | Handler for adding chest data. |
| UpdateChest | [ChestRequest](#keeper-ChestRequest) | [HistoryResponse](#keeper-HistoryResponse) | Handler for updating chest. |
| DeleteChest | [DeleteChestRequest](#keeper-DeleteChestRequest) | [HistoryResponse](#keeper-HistoryResponse) | Handler for deleting chest. |
| Sync | [SyncRequest](#keeper-SyncRequest) | [SyncResponse](#keeper-SyncResponse) | Handler for syncing history and data. |

 



<a name="keeper-proto"></a>
<p align="right"><a href="#top">Top</a></p>

## keeper.proto



<a name="keeper-AuthDataRequest"></a>

### AuthDataRequest
Represent the data required for user registration or authentification.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| login | [string](#string) |  |  |
| password | [string](#string) |  |  |






<a name="keeper-AuthTokenResponse"></a>

### AuthTokenResponse
Represent the data which client get after success registration or authentification.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| token | [string](#string) |  |  |






<a name="keeper-Chest"></a>

### Chest
Represent chest data.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| id | [string](#string) |  |  |
| user_id | [string](#string) | optional |  |
| salt | [bytes](#bytes) |  |  |
| name | [string](#string) |  |  |
| data | [bytes](#bytes) |  |  |
| datat_type | [int32](#int32) |  |  |






<a name="keeper-ChestIDRequest"></a>

### ChestIDRequest
Represent the transfered data when get chest by id.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| chest_id | [string](#string) |  |  |






<a name="keeper-ChestRequest"></a>

### ChestRequest
Represent data for chest creation/modifing requests.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| chest | [Chest](#keeper-Chest) |  |  |
| history | [History](#keeper-History) |  |  |






<a name="keeper-ChestResponse"></a>

### ChestResponse
Represent cehst response.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| chest | [Chest](#keeper-Chest) |  |  |
| history | [History](#keeper-History) |  |  |






<a name="keeper-DeleteChestRequest"></a>

### DeleteChestRequest
Represent delete chest request.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| history | [History](#keeper-History) |  |  |






<a name="keeper-History"></a>

### History
Represent history data.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| id | [string](#string) |  |  |
| chest_id | [string](#string) |  |  |
| user_id | [string](#string) | optional |  |
| operation_type | [int32](#int32) |  |  |
| operation_time | [int64](#int64) |  |  |
| syncing_time | [int64](#int64) | optional |  |
| device_name | [string](#string) |  |  |
| device_ip | [string](#string) | optional |  |






<a name="keeper-HistoryResponse"></a>

### HistoryResponse
Represent respose as history event.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| history | [History](#keeper-History) |  |  |






<a name="keeper-SyncRequest"></a>

### SyncRequest
Represent sync request that contatins list of history events.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| history | [History](#keeper-History) | repeated |  |






<a name="keeper-SyncResponse"></a>

### SyncResponse
Represent sync response that contatins list of history events.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| history | [History](#keeper-History) | repeated |  |





 

 

 


<a name="keeper-Keeper"></a>

### Keeper
Service for handling keeper features.

| Method Name | Request Type | Response Type | Description |
| ----------- | ------------ | ------------- | ------------|
| SignUp | [AuthDataRequest](#keeper-AuthDataRequest) | [AuthTokenResponse](#keeper-AuthTokenResponse) | Handler for doing user registration. |
| SignIn | [AuthDataRequest](#keeper-AuthDataRequest) | [AuthTokenResponse](#keeper-AuthTokenResponse) | Handler for doing user authentification. |
| GetChestByID | [ChestIDRequest](#keeper-ChestIDRequest) | [ChestResponse](#keeper-ChestResponse) | Handler for getting chest by id. |
| AddChest | [ChestRequest](#keeper-ChestRequest) | [HistoryResponse](#keeper-HistoryResponse) | Handler for adding chest data. |
| UpdateChest | [ChestRequest](#keeper-ChestRequest) | [HistoryResponse](#keeper-HistoryResponse) | Handler for updating chest. |
| DeleteChest | [DeleteChestRequest](#keeper-DeleteChestRequest) | [HistoryResponse](#keeper-HistoryResponse) | Handler for deleting chest. |
| Sync | [SyncRequest](#keeper-SyncRequest) | [SyncResponse](#keeper-SyncResponse) | Handler for syncing history and data. |

 



## Scalar Value Types

| .proto Type | Notes | C++ | Java | Python | Go | C# | PHP | Ruby |
| ----------- | ----- | --- | ---- | ------ | -- | -- | --- | ---- |
| <a name="double" /> double |  | double | double | float | float64 | double | float | Float |
| <a name="float" /> float |  | float | float | float | float32 | float | float | Float |
| <a name="int32" /> int32 | Uses variable-length encoding. Inefficient for encoding negative numbers – if your field is likely to have negative values, use sint32 instead. | int32 | int | int | int32 | int | integer | Bignum or Fixnum (as required) |
| <a name="int64" /> int64 | Uses variable-length encoding. Inefficient for encoding negative numbers – if your field is likely to have negative values, use sint64 instead. | int64 | long | int/long | int64 | long | integer/string | Bignum |
| <a name="uint32" /> uint32 | Uses variable-length encoding. | uint32 | int | int/long | uint32 | uint | integer | Bignum or Fixnum (as required) |
| <a name="uint64" /> uint64 | Uses variable-length encoding. | uint64 | long | int/long | uint64 | ulong | integer/string | Bignum or Fixnum (as required) |
| <a name="sint32" /> sint32 | Uses variable-length encoding. Signed int value. These more efficiently encode negative numbers than regular int32s. | int32 | int | int | int32 | int | integer | Bignum or Fixnum (as required) |
| <a name="sint64" /> sint64 | Uses variable-length encoding. Signed int value. These more efficiently encode negative numbers than regular int64s. | int64 | long | int/long | int64 | long | integer/string | Bignum |
| <a name="fixed32" /> fixed32 | Always four bytes. More efficient than uint32 if values are often greater than 2^28. | uint32 | int | int | uint32 | uint | integer | Bignum or Fixnum (as required) |
| <a name="fixed64" /> fixed64 | Always eight bytes. More efficient than uint64 if values are often greater than 2^56. | uint64 | long | int/long | uint64 | ulong | integer/string | Bignum |
| <a name="sfixed32" /> sfixed32 | Always four bytes. | int32 | int | int | int32 | int | integer | Bignum or Fixnum (as required) |
| <a name="sfixed64" /> sfixed64 | Always eight bytes. | int64 | long | int/long | int64 | long | integer/string | Bignum |
| <a name="bool" /> bool |  | bool | boolean | boolean | bool | bool | boolean | TrueClass/FalseClass |
| <a name="string" /> string | A string must always contain UTF-8 encoded or 7-bit ASCII text. | string | String | str/unicode | string | string | string | String (UTF-8) |
| <a name="bytes" /> bytes | May contain any arbitrary sequence of bytes. | string | ByteString | str | []byte | ByteString | string | String (ASCII-8BIT) |

