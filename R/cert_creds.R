#' @export
cert_assertion <- function(certificate, ...)
{
    UseMethod("cert_assertion")
}


#' @export
cert_assertion.stored_cert <- function(certificate, duration=3600, signature_size=256, ...)
{
    structure(list(cert=certificate, duration=duration, size=signature_size, claims=list(...)),
              class="cert_assertion")
}


build_assertion <- function(assertion, ...)
{
    UseMethod("build_assertion")
}


build_assertion.stored_cert <- function(assertion, ...)
{
    build_assertion(cert_assertion(assertion), ...)
}


build_assertion.cert_assertion <- function(assertion, tenant, app, aad_host, version)
{
    url <- httr::parse_url(aad_host)
    if(url$path == "")
    {
        url$path <- if(version == 1)
            file.path(tenant, "oauth2/token")
        else file.path(tenant, "oauth2/v2.0/token")
    }

    claim <- jose::jwt_claim(iss=app, sub=app, aud=httr::build_url(url),
                             exp=as.numeric(Sys.time() + assertion$duration))

    if(!is_empty(assertion$claims))
        claim <- utils::modifyList(claim, assertion$claims)

    sign_assertion(assertion$cert, claim, assertion$size)
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

    header <- list(alg=alg, x5t=certificate$x5t, kid=certificate$x5t, typ="JWT")
    token_conts <- paste(token_encode(header), token_encode(claim), sep=".")

    sig <- certificate$sign(openssl::sha2(charToRaw(token_conts), size=size), alg)
    paste(token_conts, sig, sep=".")
}

