#' @export
cert_assertion <- function(certificate, ...)
{
    UseMethod("cert_assertion")
}


#' @export
cert_assertion.stored_cert <- function(certificate, expiry_date=NULL, activation_date=NULL, signature_size=256, ...)
{
    as_num <- function(date)
    {
        if(is.null(date))
            NULL
        else as.numeric(as.POSIXct(date, origin="1970-01-01"))
    }

    claim <- jose::jwt_claim(exp=as_num(expiry_date), nbf=as_num(activation_date), ...)
    structure(list(cert=certificate, claim=claim, size=signature_size), class="cert_assertion")
}


build_assertion <- function(assertion, ...)
{
    UseMethod("build_assertion")
}


build_assertion.cert_assertion <- function(assertion, tenant, app, aad_host, version, ...)
{
    assertion$claim$iss <- app
    assertion$claim$sub <- app

    url <- httr::parse_url(aad_host)
    if(url$path == "")
    {
        url$path <- if(version == 1)
            file.path(tenant, "oauth2/token")
        else file.path(tenant, "oauth2/v2.0/token")
    }
    assertion$claim$aud <- httr::build_url(url)

    if(!is_empty(list(...)))
        assertion$claim <- utils::modifyList(claim, list(...))

    sign_assertion(assertion$cert, assertion$claim, assertion$size)
}


build_assertion.default <- function(assertion, ...)
{
    if(is.null(assertion) || (is.character(assertion) && length(assertion) == 1))
        assertion
    else stop("Invalid certificate assertion", call.=FALSE)
}


sign_assertion <- function(certificate, claim, size)
{
    UseMethod("sign_assertion")
}


sign_assertion.stored_cert <- function(certificate, claim, size)
{
    token_encode <- function(x)
    {
        jose::base64url_encode(jsonlite::toJSON(x, auto_unbox=TRUE))
    }

    kty <- certificate$policy$key_props$kty  # key type determines signing alg
    alg <- if(kty == "RSA")
        paste0("RS", size)
    else paste0("ES", size)

    header <- list(alg=alg, x5t=certificate$x5t, typ="JWT")
    token_conts <- paste(token_encode(header), token_encode(claim), sep=".")

    sig <- certificate$sign(openssl::sha2(charToRaw(token_conts), size=size), alg)
    paste(token_conts, sig, sep=".")
}

