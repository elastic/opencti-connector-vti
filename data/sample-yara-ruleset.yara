// code: language=yara insertSpaces=true tabSize=4

import "vt"

/* This is a work in progress to explore the data */
private rule email_with_attachment : email attachment
{
	strings:
		$mime_attachment = "Content-Disposition: attachment"
        $base64 = "Content-Transfer-Encoding: base64"

    condition:
        vt.metadata.file_type == vt.FileType.EMAIL and ($mime_attachment and $base64)

}

rule mime_msoffice_doc_b64 : msoffice b64encoded email attachment
{
    strings:
	    // b64 encoded {D0 CF 11 E0 A1 B1 1A E1 }
        $s0 = "0M8R4KGxGuE"

    condition:
		email_with_attachment and $s0
}

rule mime_msaccess_b64 : msoffice msaccess b64encoded email attachment
{
    strings:
        $s0 = /([\+\/0-9A-Za-z]{6}[159BFJNRVZdhlptx]TdGFuZGFyZCBKZXQgREIA)/

    condition:
        $s0 and email_with_attachment
}

/************************* OfficeXML documents *********************************/
private rule officexml_b64 : officexml email attachment
{
    strings:
        /* OfficeXML header (b64 encoded) */
        $s0 = /UEsDBBQABg[A-D]/

    condition:
        $s0 and email_with_attachment
}

rule docx_b64 : docx b64encoded officexml email attachment
{
    strings:
        $s0 = "[Content_Types].xml" base64
        $s1 = "_rels/.rels" base64
        $s2 = "word/" base64

        /* Matches b64 encoded /PK\x03\x04.{26}word\// */
        $word_header = /([\+\/0-9A-Za-z]{2}[159BFJNRVZdhlptx]QSwME[\+\/0-9A-Za-z]{34}[159BFJNRVZdhlptx]3b3JkL[\+\/-9w-z]|UEsDB[A-P][\+\/0-9A-Za-z]{34}d29yZC[\+\/89]|[\+\/0-9A-Za-z][1FVl]BLAw[Q-T][\+\/0-9A-Za-z]{34}[3HXn]dvcmQv)/

    condition:
        officexml_b64 and 1 of ($s*) and $word_header
}

rule xlsx_b64 : xlsx b64encoded officexml email attachment
{
    strings:
        $s0 = "[Content_Types].xml" base64
        $s1 = "_rels/.rels" base64
        $s2 = "xl/" base64

        /* Matches b64 encoded /PK\x03\x04.{26}xl\// */
        $excel_header = /([\+\/0-9A-Za-z][1FVl]BLAw[Q-T][\+\/0-9A-Za-z]{34}[3HXn]hsL[\+\/-9w-z]|[\+\/0-9A-Za-z]{2}[159BFJNRVZdhlptx]QSwME[\+\/0-9A-Za-z]{34}[159BFJNRVZdhlptx]4bC[\+\/89]|UEsDB[A-P][\+\/0-9A-Za-z]{34}eGwv)/

    condition:
        officexml_b64 and 1 of ($s*) and $excel_header

}

rule pptx_b64 : pptx b64encoded officexml email attachment
{
    strings:
        $s0 = "[Content_Types].xml" base64
        $s1 = "_rels/.rels" base64
        $s2 = "ppt/" base64

        /* Matches b64 encoded /PK\x03\x04.{26}ppt\// */
        $ppt_header = /(UEsDB[A-P][\+\/0-9A-Za-z]{34}cHB0L[\+\/0-9w-z]|[\+\/0-9A-Za-z][1FVl]BLAw[Q-T][\+\/0-9A-Za-z]{34}[3HXn]BwdC[\+\/89]|[\+\/0-9A-Za-z]{2}[159BFJNRVZdhlptx]QSwME[\+\/0-9A-Za-z]{34}[159BFJNRVZdhlptx]wcHQv)/

    condition:
        officexml_b64 and 1 of ($s*) and $ppt_header

}

/*********** PDF attachment ********************/
rule pdf_b64 : pdf b64encoded email attachment
{
    strings:
	    // b64 encoded %PDF file magic {25 50 44 46}
        $s0 = /JVBER[g-v]/

    condition:
		email_with_attachment and $s0
}

/************ PE attachment *********************/
rule pe32_b64 : pe32 b64encoded email attachment
{
    strings:
        // b64 encoded MZ file magic {4D 5A ??}

        $s0 = /TV[opqr][\+\/0-9A-Za-z]/

    condition:
        // This could likely be refined to include the PE
        // for any i in (1..#a): (uint32(@a[i] + uint32(@a[i] + 0x3C)) == 0x00004550)
		email_with_attachment and $s0
}
