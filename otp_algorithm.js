const {
    textToPlaincode,
    plaincodeToText,
    createOnetimePad,
    nob,
    codebook,
    checkLength,
    encryptPlaincode,
    decryptEncryptedMsg
  } = require('otp-encryption-decryption-lib');

module.exports=function(req, res){
        if (req.body.btnID === "Encrypte"){

                var txt = req.body.encrypte_input
                // var otp=req.body.encrypte_key

                if(req.body.encrypte_input===""){
                    res.render("./otp/otp.ejs");
                    return;
                }
                else{
                    try{
                        // if (isNaN(otp)){
                        //     otp=textToPlaincode(otp, nob, codebook);
                        // }
                        const plaincodeConverted = textToPlaincode(txt, nob, codebook)
                        const otp = createOnetimePad(96)
                        const lengthObj = checkLength(plaincodeConverted, otp)
                        const encryptedMsg = encryptPlaincode(plaincodeConverted, otp)
                        formated_message=encryptedMsg.join('')
                        your_message=req.body.encrypte_input
                        res.render("./otp/otp_Encr_output.ejs", {
                            message:txt,
                            plaincode:plaincodeConverted,
                            otp_key:otp,
                            cipher:formated_message
                        });
                    }
                    catch{
                        res.status(500).send('An error occurred during decryption.');
                    }
                }    
        }
        if (req.body.btnID==="Decrypte") {

            encryptedMsgs=req.body.encrypted_message
            encryptedMsgs=encryptedMsgs.split("").map(Number)
            otps=req.body.decryption_key

            if (encryptedMsgs==="" || otps==="" ){
                res.render("./otp/otp.ejs")
                return;
            }

            if (isNaN(otps)){
                otps=textToPlaincode(otps, nob, codebook);
            }
            else{
                try
                {
                    const decryptedPlaincode = decryptEncryptedMsg(encryptedMsgs.join(''), otps)
                    const textConverted = plaincodeToText(decryptedPlaincode.join(''), nob, codebook)
                        res.render("./otp/otp_Decr_output.ejs", {
                            Decrypted_plaincode:decryptedPlaincode.join(''),
                            Decrypted_msg:textConverted + '\n\n'
                        });
                  }
                    catch{
                        res.status(500).send('An error occurred during decryption.');
                    } 
            }
        }
       
    }


    