using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Text;

namespace CentrifyCLI
{
    class LRPC2Constants
    {
        public const int HANDSHAKE_PAYLOAD = 4;
        public const int HANDSHAKE_ACK = 1;
        public const UInt16 HEADER_LENGTH = 34;        
        public const UInt32 MAGIC_NUMBER = 0xABCD8012;
        public const UInt32 VERSION = 4;

        public const byte MSG_DATA_TYPE_STRING = 4;
        public const byte MSG_END = 0;
    }

    class LRPC2Header
    {
        UInt32 MagicNumber = LRPC2Constants.MAGIC_NUMBER;
        UInt16 HeaderLength = LRPC2Constants.HEADER_LENGTH;
        UInt32 Version = LRPC2Constants.VERSION;

        public UInt64 PID;
        public UInt32 SequenceNumber;
        public UInt64 Timestamp;
        public UInt32 MessageDataLength;

        public LRPC2Header(byte[] headerBytes)
        {
            if (headerBytes == null) throw new ArgumentNullException("LRPC2Header.headerBytes");

            try
            {
                using (MemoryStream ms = new MemoryStream(headerBytes))
                {
                    using (BinaryReader br = new BinaryReader(ms))
                    {
                        MagicNumber = br.ReadUInt32();
                        HeaderLength = br.ReadUInt16();
                        Version = br.ReadUInt32();
                        PID = br.ReadUInt64();
                        SequenceNumber = br.ReadUInt32();
                        Timestamp = br.ReadUInt64();
                        MessageDataLength = br.ReadUInt32();
                    }
                }
            }
            catch (Exception)
            {                
                throw;
            }
        }

        public LRPC2Header(UInt64 pID, UInt32 sequenceNumber, UInt64 timestamp, UInt32 messageDataLength)
        {
            this.PID = pID;
            this.SequenceNumber = sequenceNumber;
            this.Timestamp = timestamp;
            this.MessageDataLength = messageDataLength;
        }

        public byte[] GetBytes()
        {
            using (MemoryStream ms = new MemoryStream())
            {
                using (BinaryWriter bw = new BinaryWriter(ms))
                {
                    bw.Write((UInt32)MagicNumber);
                    bw.Write((UInt16)HeaderLength);
                    bw.Write((UInt32)Version);
                    bw.Write((UInt64)PID);
                    bw.Write((UInt32)SequenceNumber);
                    bw.Write((UInt64)Timestamp);
                    bw.Write((UInt32)MessageDataLength);
                    ms.Position = 0;
                    return ms.ToArray();
                }
            }
        }
    }
    
    class LRPC2Data
    {
        public UInt16 Command;
        public Int32 Status;
        public string Error;
        public IEnumerable<object> Payload;

        public LRPC2Data()
        {
        }

        public LRPC2Data(BinaryReader br)
        {
            DecodeData(br);
        }

        /// <summary>
        /// Return LRPC2 data bytes for this instance
        /// </summary>
        /// <returns></returns>
        public byte[] EncodeData()
        {
            using (MemoryStream ms = new MemoryStream())
            {
                using (BinaryWriter bw = new BinaryWriter(ms, Encoding.Default))
                {
                    bw.Write(Command);
                    if (Payload != null)
                    {
                        foreach (object dataItem in Payload)
                        {
                            if (dataItem == null)
                            {
                                continue;
                            }
                            Type dataItemType = dataItem.GetType();
                            if (dataItemType == typeof(string))
                            {
                                bw.Write(LRPC2Constants.MSG_DATA_TYPE_STRING);
                                SetString(dataItem as string, bw);
                            }                            
                        }
                    }
                    bw.Write(LRPC2Constants.MSG_END);
                    ms.Position = 0;
                    return ms.ToArray();
                }
            }
        }

        /// <summary>
        /// Initializes this instance using input binary stream
        /// </summary>
        /// <param name="br"></param>
        public void DecodeData(BinaryReader br)
        {
            if (br == null) throw new ArgumentNullException("DecodeData.br");

            bool eof = false;
            byte datatype;

            try
            {
                //1st data item should be the command
                Command = br.ReadUInt16();
                //2nd data item should be the status
                datatype = br.ReadByte();
                if (datatype != 2)
                {
                    throw new ApplicationException(string.Format("LRPC2 data returned unexpected status. Received value: {0} Expected value: 2", datatype));
                }
                Status = br.ReadInt32();
                //3rd data item should be the error
                datatype = br.ReadByte();
                if (datatype != 4)
                {
                    throw new ApplicationException(string.Format("LRPC2 data returned unexpected status. Received value: {0} Expected value: 4", datatype));
                }
                Error = GetString(br);
                List<object> dataitems = new List<object>();
                while (br.BaseStream.Position != br.BaseStream.Length && !eof)
                {
                    datatype = br.ReadByte();
                    switch (datatype)
                    {
                        case LRPC2Constants.MSG_END:
                            eof = true;
                            break;
                        case LRPC2Constants.MSG_DATA_TYPE_STRING:
                            string str = GetString(br);
                            if (str != null)
                            {
                                dataitems.Add(str);
                            }
                            break;                        
                    }
                }
                Payload = dataitems;
            }
            catch (Exception)
            {
                br.BaseStream.Seek(0, SeekOrigin.Begin);
                byte[] data = new byte[br.BaseStream.Length];
                br.BaseStream.Read(data, 0, Convert.ToInt32(br.BaseStream.Length));                
            }
        }

        static string GetString(BinaryReader br)
        {
            if (br == null)
            {
                throw new ArgumentNullException("GetString.br");
            }
            Int32 length = br.ReadInt32();
            if (length < 0) return null;
            return Encoding.UTF8.GetString(br.ReadBytes(length));
        }

        static void SetString(string s, BinaryWriter bw)
        {
            if (bw == null)
            {
                throw new ArgumentNullException("SetString.bw");
            }
            UInt32 length;
            if (s != null)
            {
                length = Convert.ToUInt32(s.Length);
                bw.Write(length);
                bw.Write(Encoding.UTF8.GetBytes(s));
            }
        }
    }

    /// <summary>
    /// Simple LRPC2 client to connect to an LRPC2 endpoint (such as cagent), issue commands and receive reply 
    /// </summary>
    public class LRPC2Client : IDisposable
    {
        string m_server;
        string m_pipeName;
        int m_maxMessageSize;
        NamedPipeClientStream m_pipeClient;
        static Random m_random = new Random();

        public LRPC2Client(string pipeName)            
        {
            m_server = ".";
            m_pipeName = pipeName;
        }
        
        /// <summary>
        /// Connect to the LRPC2 endpoint and perform handshake using the specified timeout
        /// </summary>
        /// <param name="connectionTimeout"></param>
        public void Connect(int connectionTimeout)
        {            
            m_pipeClient = new NamedPipeClientStream(m_server, m_pipeName);
            m_pipeClient.Connect(connectionTimeout);
            byte[] handshakePayload = BitConverter.GetBytes(LRPC2Constants.HANDSHAKE_PAYLOAD);
            m_pipeClient.Write(handshakePayload, 0, 4);
            byte[] handshakeAck = new byte[8];
            m_pipeClient.Read(handshakeAck, 0, 8);
            if (BitConverter.ToInt32(handshakeAck, 0) != LRPC2Constants.HANDSHAKE_ACK)
            {
                throw new ApplicationException(string.Format("LRPC2 handshake failed. Received Ack: {0}", Convert.ToBase64String(handshakeAck)));
            }
            m_maxMessageSize = BitConverter.ToInt32(handshakeAck, 4);            
        }

        /// <summary>
        /// Issue a command to the LRPC2 endpoint and receive the reply
        /// </summary>
        /// <param name="command">Command/Message Id</param>
        /// <param name="payload">Parameters</param>
        /// <returns></returns>
        public IEnumerable<object> SendCommandAndGetReply(UInt16 command, params object[] payload)
        {            
            uint randomSequenceNumber = (uint)m_random.Next();

            //Encode payload
            LRPC2Data data = new LRPC2Data();
            data.Command = command;
            data.Payload = payload;
            byte[] encodedData = data.EncodeData();
            if (encodedData.Length > m_maxMessageSize)
            {
                throw new ApplicationException(string.Format("LRPC2 message payload size ({0}) exceeds the maximum message size allowed ({1})", encodedData.Length, m_maxMessageSize));
            }

            //Encode header
            LRPC2Header header = new LRPC2Header((ulong)Process.GetCurrentProcess().Id, randomSequenceNumber, (ulong)DateTime.UtcNow.Ticks, Convert.ToUInt32(encodedData.Length));
            byte[] encodedHeader = header.GetBytes();

            //Join header and payload and write to the pipe
            byte[] completePayload = new byte[encodedHeader.Length + encodedData.Length];
            Array.Copy(encodedHeader, 0, completePayload, 0, encodedHeader.Length);
            Array.Copy(encodedData, 0, completePayload, encodedHeader.Length, encodedData.Length);
            m_pipeClient.Write(completePayload, 0, completePayload.Length);

            //Read response
            byte[] responseHeaderBytes = new byte[LRPC2Constants.HEADER_LENGTH];
            m_pipeClient.Read(responseHeaderBytes, 0, LRPC2Constants.HEADER_LENGTH);
            header = new LRPC2Header(responseHeaderBytes);
            if (header.SequenceNumber == randomSequenceNumber)
            {
                byte[] responseMessageBytes = new byte[header.MessageDataLength];
                m_pipeClient.Read(responseMessageBytes, 0, (int)header.MessageDataLength);
                using (MemoryStream ms = new MemoryStream(responseMessageBytes))
                {
                    using (BinaryReader br = new BinaryReader(ms))
                    {
                        data = new LRPC2Data(br);
                        return data.Payload;
                    }
                }
            }
            else
            {
                throw new ApplicationException(string.Format("Response header contained incorrect sequence number ({0}). Expected ({1})", header.SequenceNumber, randomSequenceNumber));
            }
        }

        public void Disconnect()
        {
            if (m_pipeClient != null)
            {
                m_pipeClient.Close();
                m_pipeClient.Dispose();
                m_pipeClient = null;
            }
        }

        public void Dispose()
        {
            Disconnect();
        }        
    }
}