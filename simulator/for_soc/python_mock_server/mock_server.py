
import grpc
from concurrent import futures
import sys
sys.path.append('./python_mock_server')
from com.fortinet.fortisoc.infolog import rpc_grpc_fb, RpcResponse, StatusCode, InfoLogSparseBatch
import flatbuffers

class InfoLogTransportServicer(rpc_grpc_fb.InfoLogTransportServiceServicer):
    def sendLogBatch(self, request, context):
        batch = InfoLogSparseBatch.InfoLogSparseBatch.GetRootAs(request, 0)
        print(f"in processBatchUnary, batch size is : {batch.RecordsLength()}")

        for i in range(batch.RecordsLength()):
            record = batch.Records(i)
            print(f"  Record {i}:")
            print(f"    id: {record.Id()}")
            print(f"    itime: {record.Itime()}")
            print(f"    dev_id: {record.DevId()}")
            if record.DevModel():
                print(f"    dev_model: {record.DevModel().decode('utf-8')}")
            if record.Type():
                print(f"    type: {record.Type().decode('utf-8')}")

            for j in range(record.U8Length()):
                print(f"    u8[{j}]: idx={record.U8(j).Idx()}, val={record.U8(j).Val()}")
            for j in range(record.U16Length()):
                print(f"    u16[{j}]: idx={record.U16(j).Idx()}, val={record.U16(j).Val()}")
            for j in range(record.U32Length()):
                print(f"    u32[{j}]: idx={record.U32(j).Idx()}, val={record.U32(j).Val()}")
            for j in range(record.U64Length()):
                print(f"    u64[{j}]: idx={record.U64(j).Idx()}, val={record.U64(j).Val()}")
            for j in range(record.I8Length()):
                print(f"    i8[{j}]: idx={record.I8(j).Idx()}, val={record.I8(j).Val()}")
            for j in range(record.I16Length()):
                print(f"    i16[{j}]: idx={record.I16(j).Idx()}, val={record.I16(j).Val()}")
            for j in range(record.I32Length()):
                print(f"    i32[{j}]: idx={record.I32(j).Idx()}, val={record.I32(j).Val()}")
            for j in range(record.I64Length()):
                print(f"    i64[{j}]: idx={record.I64(j).Idx()}, val={record.I64(j).Val()}")
            for j in range(record.F64Length()):
                print(f"    f64[{j}]: idx={record.F64(j).Idx()}, val={record.F64(j).Val()}")
            for j in range(record.IpLength()):
                ip_entry = record.Ip(j)
                print(f"    ip[{j}]: idx={ip_entry.Idx()}, hi={ip_entry.Hi()}, lo={ip_entry.Lo()}")
            for j in range(record.StringsLength()):
                 if record.StringIndicesLength() > j:
                     idx = record.StringIndices(j)
                 else:
                     idx = "N/A"
                 val = record.Strings(j).decode('utf-8')
                 print(f"    strings[{j}]: idx={idx}, val={val}")

        builder = flatbuffers.Builder(0)
        RpcResponse.Start(builder)
        RpcResponse.AddStatus(builder, StatusCode.StatusCode.OK)
        response = RpcResponse.End(builder)
        builder.Finish(response)
        return bytes(builder.Output())

def serve():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    rpc_grpc_fb.add_InfoLogTransportServiceServicer_to_server(InfoLogTransportServicer(), server)
    server.add_insecure_port('[::]:19999')
    server.start()
    print("Server started on port 19999")
    server.wait_for_termination()

if __name__ == '__main__':
    serve()
