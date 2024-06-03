from pydantic import BaseModel, Field


class CodeDeliveryDetails(BaseModel):
    destination: str = Field(alias='Destination')
    delivery_medium: str = Field(alias='DeliveryMedium')
    attribute_name: str = Field(alias='AttributeName')


class CodeDeliveryDetailsSchema(BaseModel):
    delivery_details: CodeDeliveryDetails = Field(alias='CodeDeliveryDetails')


class UserRegister(BaseModel):
    confirmed: bool = Field(alias='UserConfirmed')
    delivery_details: CodeDeliveryDetails = Field(alias='CodeDeliveryDetails')
    user_id: str = Field(alias='UserSub')
