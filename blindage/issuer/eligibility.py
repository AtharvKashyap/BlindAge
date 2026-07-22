from datetime import date

from blindage.schemas import CLAIM_MIN_AGE, AgeClaim


def _age_in_years(date_of_birth: date, today: date) -> int:
    years = today.year - date_of_birth.year
    # Subtract one if this year's birthday hasn't happened yet. A Feb 29
    # birthday is treated as Mar 1 in non-leap years.
    birthday_passed = (today.month, today.day) >= (date_of_birth.month, date_of_birth.day)
    return years if birthday_passed else years - 1


def eligible_claims(date_of_birth: date, today: date) -> set[AgeClaim]:
    age = _age_in_years(date_of_birth, today)
    return {claim for claim, min_age in CLAIM_MIN_AGE.items() if age >= min_age}
