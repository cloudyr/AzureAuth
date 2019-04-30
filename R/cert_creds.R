#' @export
cert_assertion <- function(certificate, ...)
{
    UseMethod("cert_assertion")
}


#' @export
cert_assertion.stored_cert <- function(certificate, expiry_date=NULL, activation_date=NULL, signature_size=256, ...)
{
    claim <- jose::jwt_claim(exp=expiry_date, nbf=activation_date, ...)
    structure(list(cert=certificate, claim=claim, size=signature_size), class="cert_assertion")
}


build_assertion <- function(assertion, ...)
{
    UseMethod("build_assertion")
}


build_assertion.cert_assertion <- function(assertion, tenant, app, aad_host, version, ...)
{
    assertion$claims$iss <- app
    assertion$claims$sub <- app

    url <- httr::parse_url(aad_host)
    if(url$path != "")
    {
        url$path <- if(version == 1)
            file.path(tenant, "oauth2/token")
        else file.path(tenant, "oauth2/v2.0/token")
    }
    assertion$claims$aud <- httr::build_url(url)

    if(!is_empty(list(...)))
        assertion$claims <- utils::modifyList(claims, list(...))

    sign_assertion(assertion$certificate, assertion$claims, assertion$size)
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

    kty <- creds$cert$policy$key_props$kty  # key type determines signing alg
    alg <- if(kty == "RSA")
        paste0("RS", size)
    else paste0("ES", size)

    header <- list(alg=alg, x5t=certificate$x5t, typ="JWT")
    token_conts <- paste(token_encode(header), token_encode(creds$claim), sep=".")

    sig <- certificate$sign(openssl::sha2(charToRaw(token_conts), size=size), alg)
    paste(token_conts, sig, sep=".")
}

