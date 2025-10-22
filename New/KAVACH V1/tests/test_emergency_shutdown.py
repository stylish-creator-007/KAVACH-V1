from src.core.emergency_controller import EmergencyController


def test_emergency_shutdown_triggers_true():
    ec = EmergencyController()
    assert ec.trigger_shutdown() is True
