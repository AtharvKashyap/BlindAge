from datetime import date

from blindage.issuer.eligibility import eligible_claims
from blindage.schemas import AgeClaim

TODAY = date(2026, 7, 21)  # Note: This date is referenced in the brief


def test_25_year_old_gets_all_claims():
    assert eligible_claims(date(2000, 1, 1), TODAY) == {
        AgeClaim.AGE_OVER_13,
        AgeClaim.AGE_OVER_16,
        AgeClaim.AGE_OVER_18,
        AgeClaim.AGE_OVER_21,
    }


def test_19_year_old_gets_up_to_18():
    assert eligible_claims(date(2007, 7, 21), TODAY) == {
        AgeClaim.AGE_OVER_13,
        AgeClaim.AGE_OVER_16,
        AgeClaim.AGE_OVER_18,
    }


def test_birthday_boundary_day_before_and_day_of():
    # Turns 18 exactly on TODAY.
    assert AgeClaim.AGE_OVER_18 in eligible_claims(date(2008, 7, 21), TODAY)
    # Still 17 the day before the birthday.
    assert AgeClaim.AGE_OVER_18 not in eligible_claims(date(2008, 7, 22), TODAY)


def test_12_year_old_gets_nothing():
    assert eligible_claims(date(2014, 1, 1), TODAY) == set()


def test_leap_day_birthday():
    # Born 2008-02-29; on 2026-02-28 still 17, on 2026-03-01 is 18.
    assert AgeClaim.AGE_OVER_18 not in eligible_claims(date(2008, 2, 29), date(2026, 2, 28))
    assert AgeClaim.AGE_OVER_18 in eligible_claims(date(2008, 2, 29), date(2026, 3, 1))


def test_boundary_13_16_21():
    # Turns exactly N on TODAY → claim granted; day before → withheld.
    for years, claim in ((13, AgeClaim.AGE_OVER_13), (16, AgeClaim.AGE_OVER_16), (21, AgeClaim.AGE_OVER_21)):
        dob_exact = date(TODAY.year - years, TODAY.month, TODAY.day)
        dob_short = date(TODAY.year - years, TODAY.month, TODAY.day + 1)
        assert claim in eligible_claims(dob_exact, TODAY)
        assert claim not in eligible_claims(dob_short, TODAY)


def test_future_dob_yields_no_claims():
    assert eligible_claims(date(TODAY.year + 1, 1, 1), TODAY) == set()
