from pydantic import BaseModel, Field

class TwoFASetupResponse(BaseModel):
    secret: str
    provisioning_uri: str
    method: str = "TOTP"

class TwoFAEnableRequest(BaseModel):
    code: str = Field(min_length=6, max_length=8)

class TwoFAVerifyRequest(BaseModel):
    code: str = Field(min_length=6, max_length=8)
