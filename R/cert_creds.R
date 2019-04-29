cert_creds <- function(certificate, ...)
{
    UseMethod("cert_creds")
}


cert_creds.stored_cert <- function(certificate, expiry_date=NULL, activation_date=NULL, key_size=256, ...)
{
    claim <- jose::jwt_claim(exp=expiry_date, nbf=activation_date, ...)
    structure(list(cert=certificate, claim=claim, size=key_size), class="cert_creds")
}


sign_creds <- function(creds, ...)
{
    UseMethod("sign_cert")
}


sign_creds.cert_creds <- function(creds, ...)
{
    token_encode <- function(x)
    {
        jose::base64url_encode(jsonlite::toJSON(x, auto_unbox=TRUE))
    }

    header <- list(alg=creds$alg, x5t=creds$cert$x5t, typ="JWT")
    token_conts <- paste(token_encode(header), token_encode(creds$claim), sep=".")

    kty <- creds$cert$policy$key_props$kty  # key type determines signing alg
    alg <- if(kty == "RSA")
        paste0("RS", creds$size)
    else paste0("ES", creds$size)

    sig <- creds$cert$sign(openssl::sha2(charToRaw(token_conts), size=creds$size), alg)
    paste(token_conts, sig, sep=".")
}


build_claims <- function(creds, tenant, app, aad_host, version, ...)
{
    claims <- creds$claims
    claims$iss <- app
    claims$sub <- app

    url <- httr::parse_url(aad_host)
    url$path <- if(version == 1)
        file.path(tenant, "oauth2/token")
    else file.path(tenant, "oauth2/v2.0/token")
    claims$aud <- httr::build_url(url)

    if(!is_empty(list(...)))
        claims <- utils::modifyList(claims, list(...))
    claims
}
