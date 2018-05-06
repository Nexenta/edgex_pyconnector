#!/bin/bash

S3EDGEX=../s3edgex/s3edgex

if [ -f s3edgex.log ]; then
	rm s3edgex.log
fi

S3EDGEX store 
S3EDGEX store primary
S3EDGEX list 
S3EDGEX list edgex://edge-FO-T/
S3EDGEX gend -l dirone/

S3EDGEX exists edgex://edge-FO-T/signer.py
S3EDGEX info edgex://edge-FO-T/signer.py
S3EDGEX get -l edgex://edge-FO-T/signer.py signer.py
S3EDGEX del edgex://edge-FO-T/signer.py
S3EDGEX put -l edgex://edge-FO-T/signer.py signer.py
S3EDGEX del -l signer.py
S3EDGEX exists edgex://edge-FO-T/signer.py
S3EDGEX info edgex://edge-FO-T/signer.py

S3EDGEX put -r -l edgex://edge-FO-T/dirone/ dirone/
S3EDGEX list -r edgex://edge-FO-T/dirone/ 
S3EDGEX info -r edgex://edge-FO-T/dirone/
S3EDGEX get -r -l edgex://edge-FO-T/dirone/ dirtwo/
S3EDGEX del -r edgex://edge-FO-T/dirone/
S3EDGEX exists -r -l dirone/
S3EDGEX info -r -l dirone/
S3EDGEX del -r -l dirtwo/
S3EDGEX del -r -l dirone/


