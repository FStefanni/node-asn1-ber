
export class InvalidAsn1Error
    extends Error
{
    constructor (msg?: string) {
        super(msg)
        this.name = 'InvalidAsn1Error'
    }
}
