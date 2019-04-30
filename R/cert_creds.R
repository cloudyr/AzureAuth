#' @export
cert_assertion <- function(certificate, duration=3600, signature_size=256, ...)
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


build_assertion.character <- function(assertion, ...)
{
    pair <- read_cert_pair(assertion)
    build_assertion(cert_assertion(pair), ...)
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
    if(is.null(assertion))
        assertion
    else stop("Invalid certificate assertion", call.=FALSE)
}


sign_assertion <- function(certificate, claim, size)
{
    UseMethod("sign_assertion")
}


sign_assertion.stored_cert <- function(certificate, claim, size)
{
    kty <- certificate$policy$key_props$kty  # key type determines signing alg
    alg <- if(kty == "RSA")
        paste0("RS", size)
    else paste0("ES", size)

    header <- list(alg=alg, x5t=certificate$x5t, kid=certificate$x5t, typ="JWT")
    token_conts <- paste(token_encode(header), token_encode(claim), sep=".")

    paste(token_conts, certificate$sign(openssl::sha2(charToRaw(token_conts), size=size), alg), sep=".")
}


sign_assertion.openssl_cert_pair <- function(certificate, claim, size)
{
    alg <- if(inherits(certificate$key, "rsa"))
        paste0("RS", size)
    else if(inherits(certificate$key, "ecdsa"))
        paste0("EC", size)
    else stop("Unsupported key type", call.=FALSE)

    x5t <- jose::base64url_encode(openssl::sha1(certificate$cert))
    header <- list(x5t=x5t, kid=x5t)

    jose::jwt_encode_sig(claim, certificate$key, size=size, header=header)
}


sign_assertion.character <- function(certificate, claim, size)
{
    pair <- read_cert_pair(certificate)
    sign_assertion(pair, claim, size)
}


read_cert_pair <- function(file)
{
    pem <- openssl::read_pem(file)
    obj <- list(
        key=openssl::read_key(pem[["PRIVATE KEY"]]),
        cert=openssl::read_cert(pem[["CERTIFICATE"]])
    )
    structure(obj, class="openssl_cert_pair")
}


token_encode <- function(x)
{
    jose::base64url_encode(jsonlite::toJSON(x, auto_unbox=TRUE))
}
